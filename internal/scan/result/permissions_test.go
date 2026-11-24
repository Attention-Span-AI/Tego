// SPDX-License-Identifier: Apache-2.0

package result

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSavedScanGroupWritableParentRefused(t *testing.T) {
	home, s, _ := stored(t)
	if err := os.Chmod(filepath.Join(home, ".tego"), 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, s.As.UID, "", s.Finished); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Read: %v", err)
	}
	if err := Save(home, s.As.UID, s); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Save: %v", err)
	}
}

func TestGroupRefusalSourceContract(t *testing.T) {
	for _, tc := range []struct {
		name, group, reason, state string
		valid                      bool
	}{
		{"named", "Private.Group$", "mode", "not-read", true},
		{"numeric", "gid 12345", "mode", "partial", true},
		{"empty", "", "mode", "not-read", false},
		{"control", "group\nforged", "mode", "not-read", false},
		{"too-long", strings.Repeat("a", 257), "mode", "not-read", false},
		{"wrong-reason", "person", "owner", "not-read", false},
		{"read", "person", "mode", "read", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := example(t)
			s.Status = "partial"
			s.Sources = append(s.Sources, Source{ID: "group-refusal", Kind: "D", Locator: Path("/fixture/settings.json"), State: tc.state, Reason: tc.reason, WritableGroup: Path(tc.group), NotRead: 1})
			// Path maps empty strings to nil; the wire field must still refuse an empty supplied group.
			if tc.group == "" {
				s.Sources[len(s.Sources)-1].WritableGroup = &tc.group
			}
			b, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			_, e = Decode(b)
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, e)
			}
		})
	}
}

func TestGroupEvidenceContract(t *testing.T) {
	for _, tc := range []struct {
		name, code, kind string
		group            bool
		valid            bool
	}{
		{"shared", "shared-primary", "F", true, true},
		{"directory service", "directory-service", "D", true, true},
		{"unknown", "invented", "D", true, false},
		{"missing group", "accounts-limit", "D", false, false},
		{"metadata", "shared-primary", "meta", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := example(t)
			s.Status = "partial"
			src := Source{ID: "refusal", Kind: tc.kind, Locator: Path("/fixture/settings.json"), State: "not-read", Reason: "mode", GroupEvidence: tc.code, NotRead: 1}
			if tc.group {
				src.WritableGroup = Path("person")
			}
			s.Sources = append(s.Sources, src)
			b, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Decode(b); (e == nil) != tc.valid {
				t.Fatalf("valid %v: %v", tc.valid, e)
			}
		})
	}
}

func TestAccountCollectionRepair(t *testing.T) {
	s := example(t)
	s.Sources = []Source{{ID: "changed-accounts", Kind: "D", Locator: Path("/fixture/settings.json"), State: "not-read", Reason: "mode", WritableGroup: Path("gid 1000"), GroupEvidence: "accounts-unreadable", NotRead: 1}}
	var out strings.Builder
	if err := Footer(&out, s, false); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"changed during collection", "run the scan again", "group \"gid 1000\"", "chmod g-w -- /fixture/settings.json"} {
		if !strings.Contains(text, want) {
			t.Errorf("footer lacks %q: %s", want, text)
		}
	}
}

func TestAccountPlacementRepairContract(t *testing.T) {
	for _, tc := range []struct {
		name, repair, code string
		valid              bool
	}{
		{"named", "Ask the administrator to repair /etc/group: group or other writable; require root ownership and remove group/other write bits.", "accounts-unreadable", true},
		{"control", "repair\nforged", "accounts-unreadable", false},
		{"over-limit", strings.Repeat("x", 2049), "accounts-unreadable", false},
		{"wrong-evidence", "repair /etc/group", "shared-primary", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := example(t)
			s.Status = "partial"
			s.Sources = append(s.Sources, Source{ID: "placement", Kind: "D", Locator: Path("/fixture/settings.json"), State: "not-read", Reason: "mode", WritableGroup: Path("gid 1000"), GroupEvidence: tc.code, AccountRepair: tc.repair, NotRead: 1})
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(b)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if tc.valid {
				var out strings.Builder
				if err := Footer(&out, got, false); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), tc.repair) {
					t.Fatalf("lost account placement repair: %s", out.String())
				}
			}
		})
	}
}

func TestAdvancedGroupRefusalRoundTrip(t *testing.T) {
	for _, kind := range []string{"system", "cron"} {
		t.Run(kind, func(t *testing.T) {
			s := advancedExample(t)
			s.Status = "partial"
			s.Sources = append(s.Sources, Source{ID: "group-refusal", Kind: kind, Locator: Path("/fixture/agent"), State: "not-read", Reason: "mode", WritableGroup: Path("staff"), GroupEvidence: "shared-primary", NotRead: 1})
			b, err := Encode(s)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(b)
			if err != nil || got.Sources[len(got.Sources)-1].GroupEvidence != "shared-primary" {
				t.Fatalf("lost advanced refusal: %v", err)
			}
			s.Mode, s.Catalog = "basic", "c3"
			if _, err := Encode(s); err == nil {
				t.Fatal("advanced source accepted in basic scope")
			}
		})
	}
}
