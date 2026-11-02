// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	agentSchema = filepath.Join("..", "..", "..", "spec", "agent", "v0", "agent.schema.json")
	examplesDir = filepath.Join("..", "..", "..", "examples", "agents")
)

func decodeYAML(t *testing.T, path string) any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

// TestExamplesValidateAgainstSchema: every examples/agents/*.yaml, read as the JSON it encodes to, satisfies
// spec/agent/v0/agent.schema.json under the real validator. pkg/spec/agent's agreement tests hold the schema to
// the Go types; this holds the shipped examples to the schema, read by an implementation of JSON Schema that is
// not ours.
func TestExamplesValidateAgainstSchema(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(examplesDir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 5 {
		t.Fatalf("found %d examples under %s, want the shipped set", len(files), examplesDir)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			Validate(t, agentSchema, decodeYAML(t, f))
		})
	}
}

// TestValidatorRefusesWhatTheSchemaRefuses: the validator is not a rubber stamp. Each document below breaks one
// rule of agent.schema.json (a required field, an unknown key at the top and in a nested object, a pattern, a
// constant, an enum, a minimum length), and Check names a refusal for it; and the ones that break nothing pass.
func TestValidatorRefusesWhatTheSchemaRefuses(t *testing.T) {
	good := map[string]any{"version": 0, "name": "a-1", "command": []any{"/bin/true"}}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, doc := range map[string]any{
		"minimal":                good,
		"cpu number":             with("limits", map[string]any{"cpu": 4}),
		"cpu fraction":           with("limits", map[string]any{"cpu": 0.5}),
		"cpu string":             with("limits", map[string]any{"cpu": "2.0"}),
		"cpu minimum":            with("limits", map[string]any{"cpu": 0.01}),
		"cpu maximum":            with("limits", map[string]any{"cpu": 175921860}),
		"env.set":                with("env", map[string]any{"set": map[string]any{"A": "x y"}}),
		"extends name":           with("extends", "base/py"),
		"extends list":           with("extends", []any{"tego/base", "team", "a", "b", "c", "d", "e", "f"}),
		"extends a revision pin": with("extends", []any{"tego/no-secrets@1", "team"}),
	} {
		if err := Check(agentSchema, doc); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}
	for name, doc := range map[string]any{
		"missing command":             with("command", nil),
		"unknown top-level key":       with("surprise", true),
		"name pattern":                with("name", "Not Lower"),
		"version const":               with("version", 1),
		"tier enum":                   with("tier", "ring0"),
		"empty command":               with("command", []any{}),
		"empty command word":          with("command", []any{""}),
		"nested unknown key":          with("fs", map[string]any{"surprise": true}),
		"not an object":               []any{"x"},
		"wrong type for boolean":      with("io_uring", "yes"),
		"cpu zero":                    with("limits", map[string]any{"cpu": 0}),
		"cpu below the range":         with("limits", map[string]any{"cpu": 0.001}),
		"cpu above the range":         with("limits", map[string]any{"cpu": 1e12}),
		"cpu negative":                with("limits", map[string]any{"cpu": -1}),
		"cpu not a number":            with("limits", map[string]any{"cpu": "many"}),
		"env.set NUL":                 with("env", map[string]any{"set": map[string]any{"A": "x\x00y"}}),
		"env.set newline":             with("env", map[string]any{"set": map[string]any{"A": "x\ny"}}),
		"extends empty list":          with("extends", []any{}),
		"extends nine names":          with("extends", []any{"a", "b", "c", "d", "e", "f", "g", "h", "i"}),
		"extends bad name":            with("extends", []any{"base", "/etc/passwd"}),
		"extends dot segment":         with("extends", []any{"base", "base/./py"}),
		"extends a pin outside tego/": with("extends", []any{"base@1"}),
		"extends a zero pin":          with("extends", "tego/no-prod@0"),
		"extends mapping":             with("extends", map[string]any{"a": 1}),
	} {
		t.Run(name, func(t *testing.T) {
			err := Check(agentSchema, doc)
			if err == nil {
				t.Fatal("the validator accepted a document the schema refuses")
			}
			if !strings.Contains(err.Error(), "does not satisfy") {
				t.Fatalf("refusal does not name the schema violation: %v", err)
			}
		})
	}
}

// TestCheckReportsAnUnusableSchema: a missing schema file and one that is not JSON are errors, not passes.
func TestCheckReportsAnUnusableSchema(t *testing.T) {
	if err := Check(filepath.Join(t.TempDir(), "absent.json"), map[string]any{}); err == nil {
		t.Error("a missing schema file passed")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(bad, map[string]any{}); err == nil {
		t.Error("a schema that is not JSON passed")
	}
}

// TestCheckRefusesAnUnencodableDocument: a document encoding/json cannot marshal is an error.
func TestCheckRefusesAnUnencodableDocument(t *testing.T) {
	if err := Check(agentSchema, map[string]any{"c": make(chan int)}); err == nil {
		t.Error("an unencodable document passed")
	}
}
