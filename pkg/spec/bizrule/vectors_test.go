// SPDX-License-Identifier: Apache-2.0

package bizrule

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fixture struct {
	ID             string          `json:"id"`
	Group          string          `json:"group"`
	Bundle         json.RawMessage `json:"bundle"`
	Request        json.RawMessage `json:"request"`
	BundleWireHex  *string         `json:"bundle_wire_hex"`
	RequestWireHex *string         `json:"request_wire_hex"`
	Expected       Result          `json:"expected"`
}

func fixtures(t testing.TB) []fixture {
	t.Helper()
	files, err := filepath.Glob("../../../spec/policy/bizrule/v1/vectors/*/*.json")
	if err != nil || len(files) != 218 {
		t.Fatalf("inventory %d: %v", len(files), err)
	}
	all := make([]fixture, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var f fixture
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		all = append(all, f)
	}
	return all
}

// Fixtures are form JSON, not literal wire bytes. Only test code canonicalizes
// their embedded JSON with UseNumber; production never repairs an input token.
func fixtureCanonical(t testing.TB, raw []byte) []byte {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func fixtureWires(t testing.TB, f fixture) ([]byte, []byte) {
	t.Helper()
	b := fixtureCanonical(t, f.Bundle)
	r := append(fixtureCanonical(t, f.Request), '\n')
	if f.BundleWireHex != nil {
		var err error
		b, err = hex.DecodeString(*f.BundleWireHex)
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.RequestWireHex != nil {
		var err error
		r, err = hex.DecodeString(*f.RequestWireHex)
		if err != nil {
			t.Fatal(err)
		}
	}
	return b, r
}
func TestVectors(t *testing.T) {
	counts := map[string]int{}
	for _, f := range fixtures(t) {
		counts[f.Group]++
		t.Run(f.Group+"/"+f.ID, func(t *testing.T) {
			b, wire := fixtureWires(t, f)
			request, err := DecodeRequest(wire)
			var got Result
			if err != nil {
				context, err := DecodeRequest(append(fixtureCanonical(t, f.Request), '\n'))
				if err != nil {
					t.Fatal(err)
				}
				got, err = LocalRefusal(context)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				got, err = Evaluate(b, request)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(got, f.Expected) {
				actual, _ := json.Marshal(got)
				expected, _ := json.Marshal(f.Expected)
				t.Fatalf("got  %s\nwant %s", actual, expected)
			}
			encoded, err := EncodeResult(got)
			if err != nil {
				t.Fatal(err)
			}
			expectedJSON, err := json.Marshal(f.Expected)
			if err != nil {
				t.Fatal(err)
			}
			expectedBytes := fixtureCanonical(t, expectedJSON)
			if !bytes.Equal(encoded, expectedBytes) {
				t.Fatalf("canonical result differs\ngot %s\nwant %s", encoded, expectedBytes)
			}
			if request.valid && !bytes.Equal(request.Canonical(), wire) {
				t.Fatal("request round trip")
			}
			if bundle, err := DecodeBundle(b); err == nil && !bytes.Equal(bundle.Canonical(), b) {
				t.Fatal("bundle round trip")
			}
		})
	}
	want := map[string]int{"bundle": 22, "composition": 32, "cumulative": 28, "limits": 22, "money": 26, "parser": 65, "scope": 23}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("group inventory %v", counts)
	}
	t.Logf("vectors by group: %v", counts)
}
