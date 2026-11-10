// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestGuardYAML: each decode yaml.v3 panics on (a list or a mapping as a key where a merge key applies, at both of
// its lines) comes back as an error; an error or nil from the decode is returned as it is, and any other panic is
// raised again.
func TestGuardYAML(t *testing.T) {
	var s struct {
		A int `yaml:"a"`
	}
	var m map[string]any
	var a any
	var n yaml.Node
	if err := yaml.Unmarshal([]byte("{<<,[]}"), &n); err != nil {
		t.Fatal(err)
	}
	for name, decode := range map[string]func() error{
		"a struct, beside the merge key (decode.go:966)":      func() error { return yaml.Unmarshal([]byte("{<<,[]}"), &s) },
		"a map, a mapping key (decode.go:966)":                func() error { return yaml.Unmarshal([]byte("<<:\n? ?"), &m) },
		"an interface, in the merged mapping (decode.go:835)": func() error { return yaml.Unmarshal([]byte("{<<: {[]: 0}, 1: 2}"), &a) },
		"a node decoded into a struct":                        func() error { return n.Decode(&s) },
	} {
		if err := GuardYAML(decode); !errors.Is(err, errYAMLMergeKey) {
			t.Errorf("%s: %v, want %v", name, err, errYAMLMergeKey)
		}
	}
	other := errors.New("other")
	if err := GuardYAML(func() error { return other }); err != other {
		t.Errorf("an error came back as %v", err)
	}
	if err := GuardYAML(func() error { return yaml.Unmarshal([]byte("a: 1\n"), &s) }); err != nil || s.A != 1 {
		t.Errorf("a good document: %v, %+v", err, s)
	}
	defer func() {
		if r := recover(); r != "not yaml's" {
			t.Errorf("another panic came out as %v", r)
		}
	}()
	_ = GuardYAML(func() error { panic("not yaml's") })
	t.Error("another panic was swallowed")
}
