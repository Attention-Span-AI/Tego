// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

type schemaObject struct {
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
}

// TestReasonFileSchemaMatchesGo: spec/reason/v1/reason-file.schema.json is the file's published shape and File and
// Entry are what Encode writes; every json key of each is a property of the other's object, and the keys that are
// always written (no omitempty) are exactly the required ones. This agreement test keeps the two from drifting meanwhile.
func TestReasonFileSchemaMatchesGo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "reason", "v1", "reason-file.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		schemaObject
		Defs struct {
			Entry schemaObject `json:"entry"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		obj  schemaObject
	}{
		{"File", reflect.TypeFor[File](), root.schemaObject},
		{"Entry", reflect.TypeFor[Entry](), root.Defs.Entry},
	} {
		keys, required := jsonKeys(tc.typ)
		props := make([]string, 0, len(tc.obj.Properties))
		for k := range tc.obj.Properties {
			props = append(props, k)
		}
		slices.Sort(keys)
		slices.Sort(props)
		if !slices.Equal(keys, props) {
			t.Errorf("%s's json keys %v, the schema's properties %v", tc.name, keys, props)
		}
		slices.Sort(required)
		want := slices.Sorted(slices.Values(tc.obj.Required))
		if !slices.Equal(required, want) {
			t.Errorf("%s's always-written keys %v, the schema's required %v", tc.name, required, want)
		}
	}
	var v struct {
		Const int `json:"const"`
	}
	if err := json.Unmarshal(root.Properties["v"], &v); err != nil || v.Const != Version {
		t.Errorf("the schema's v is %d (%v), want %d", v.Const, err, Version)
	}
	var recent struct {
		MaxItems int `json:"maxItems"`
	}
	if err := json.Unmarshal(root.Properties["recent"], &recent); err != nil || recent.MaxItems != RingSize {
		t.Errorf("the schema's recent maxItems is %d (%v), want %d", recent.MaxItems, err, RingSize)
	}
}
