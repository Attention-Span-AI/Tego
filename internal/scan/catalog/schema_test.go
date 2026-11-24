// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
)

const scanSchemaPath = "../../../spec/scan/v1/schema.json"

// TestScanSchema checks the second reading's structural contract with the repository's
// independent validator. It is a synthetic schema fixture, not command-output proof.
func TestScanSchema(t *testing.T) {
	b, e := os.ReadFile("../../../spec/scan/v1/fixtures/basic.json")
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"valid", nil},
		{"unreadable warning required", func(r map[string]any) { delete(r, "unreadable_programs_warning") }},
		{"unreadable warning fixed", func(r map[string]any) { r["unreadable_programs_warning"] = "All programs are classified." }},
		{"relative path", func(r map[string]any) { r["project"] = "relative" }},
		{"control path", func(r map[string]any) { r["project"] = "/home/\x1ba" }},
		{"bidi path", func(r map[string]any) { r["project"] = "/home/a\u200fb" }},
		{"version required", func(r map[string]any) { delete(r, "tego") }},
		{"catalog revision", func(r map[string]any) { r["catalog"] = "2026-11-11" }},
		{"counts replace matched", func(r map[string]any) { r["matched"] = 1 }},
		{"copied item text", func(r map[string]any) { r["items"].([]any)[0].(map[string]any)["name"] = "node --token=secret" }},
		{"copied evidence text", func(r map[string]any) {
			r["items"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["name"] = "secret"
		}},
		{"run id grammar", func(r map[string]any) {
			r["items"].([]any)[0].(map[string]any)["detail"].(map[string]any)["run_id"] = "secret"
		}},
		{"unit grammar", func(r map[string]any) {
			r["items"].([]any)[0].(map[string]any)["detail"].(map[string]any)["unit"] = "python --key=secret"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r map[string]any
			if e := json.Unmarshal(b, &r); e != nil {
				t.Fatal(e)
			}
			if tc.change != nil {
				tc.change(r)
			}
			e := jsonschema.Check(scanSchemaPath, r)
			if tc.change == nil && e != nil {
				t.Fatal(e)
			}
			if tc.change != nil && e == nil {
				t.Fatal("schema accepted invalid shape")
			}
		})
	}
}

func TestProjectSchema(t *testing.T) {
	b, e := os.ReadFile("../../../spec/scan/v1/fixtures/project.json")
	if e != nil {
		t.Fatal(e)
	}
	var r map[string]any
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	if e = jsonschema.Check(scanSchemaPath, r); e != nil {
		t.Fatal(e)
	}
	items := r["items"].([]any)
	last := items[len(items)-1].(map[string]any)
	last["detail"].(map[string]any)["dependency"] = "uncatalogued"
	if jsonschema.Check(scanSchemaPath, r) == nil {
		t.Fatal("open dependency id")
	}
}

func TestConfiguredSchema(t *testing.T) {
	b, e := os.ReadFile("../../../spec/scan/v1/fixtures/configured.json")
	if e != nil {
		t.Fatal(e)
	}
	var wire any
	if e = json.Unmarshal(b, &wire); e != nil {
		t.Fatal(e)
	}
	if e = jsonschema.Check(scanSchemaPath, wire); e != nil {
		t.Fatal(e)
	}
}

func TestConfiguredLocalAndUnresolvedSchema(t *testing.T) {
	b, e := os.ReadFile("../../../spec/scan/v1/fixtures/configured.json")
	if e != nil {
		t.Fatal(e)
	}
	var wire map[string]any
	if e = json.Unmarshal(b, &wire); e != nil {
		t.Fatal(e)
	}
	item := wire["items"].([]any)[0].(map[string]any)
	item["name"] = "claude"
	detail := item["detail"].(map[string]any)
	detail["scope"], detail["client"] = "local", "claude"
	if e = jsonschema.Check(scanSchemaPath, wire); e != nil {
		t.Fatalf("local scope rejected: %v", e)
	}
	wire["status"], wire["check"] = "partial", "unknown"
	wire["sources"] = append(wire["sources"].([]any), map[string]any{
		"id": "unresolved-unit", "kind": "E", "locator": "/fixtures/expand.service",
		"state": "not-read", "read": 0, "not_read": 1, "reason": "unresolved",
	})
	if e = jsonschema.Check(scanSchemaPath, wire); e != nil {
		t.Fatalf("unresolved source rejected: %v", e)
	}
}
