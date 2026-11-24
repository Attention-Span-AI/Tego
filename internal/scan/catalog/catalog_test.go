// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"reflect"
	"testing"
)

func TestEveryDefaultHasCatalogRow(t *testing.T) {
	rows := Rows()
	defaults := sig.Default()
	if len(rows) != 9 || len(rows) != len(defaults) {
		t.Fatalf("catalog size %d", len(rows))
	}
	seen := map[string]bool{}
	for i, r := range rows {
		if seen[r.ID] {
			t.Fatal("duplicate rule id")
		}
		seen[r.ID] = true
		if !reflect.DeepEqual(r.Rule, defaults[i]) {
			t.Fatalf("default %d differs: %+v", i, r)
		}
		if err := r.Rule.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	rows[0].Rule.Name = "changed"
	rows[1].Rule.Argv[0] = "changed"
	if reflect.DeepEqual(rows, Rows()) || !reflect.DeepEqual(Rows()[1].Rule, defaults[1]) {
		t.Fatal("catalog aliases caller memory")
	}
}

func TestObservedNamesAreClosed(t *testing.T) {
	for _, tc := range []struct {
		id, name string
		ok       bool
	}{
		{"claude-native", "claude", true}, {"user-1", "user-1", true}, {"user-64", "user-64", true},
		{"user-0", "", false}, {"user-01", "", false}, {"user-65", "", false}, {"MARKER_SECRET", "", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			v, ok := ObservedName(tc.id)
			if v != tc.name || ok != tc.ok {
				t.Fatalf("observed name %q %v", v, ok)
			}
		})
	}
}
