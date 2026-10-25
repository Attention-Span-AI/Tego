// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGateThresholdBoundsAgreeWithCompile: gate.New refuses allow < 1 since the
// bands were built as written (ADR 0007), but the published agent.schema.json and the loader's schema
// tree still took thresholds.allow 0, so an editor validating against the schema accepted a contract compile refused.
// Each threshold's schema range is now exactly the values some valid pair takes (1 <= allow < ask <= 100): allow
// 1..99, ask 2..100, in the JSON schema and in the loader alike.
func TestGateThresholdBoundsAgreeWithCompile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "spec", "agent", "v0", "agent.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Properties struct {
			Gate struct {
				Properties struct {
					Thresholds struct {
						Description string `json:"description"`
						Properties  map[string]struct {
							Minimum, Maximum int
						} `json:"properties"`
					} `json:"thresholds"`
				} `json:"properties"`
			} `json:"gate"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	th := root.Properties.Gate.Properties.Thresholds
	if !strings.Contains(th.Description, "1 <= allow < ask <= 100") {
		t.Errorf("thresholds description %q does not state the pair's rule", th.Description)
	}
	for _, tc := range []struct {
		key  string
		pair func(v int) string // the thresholds with key at v and the other at a value that pairs with every valid v
	}{
		{"allow", func(v int) string { return "{thresholds: {allow: " + strconv.Itoa(v) + ", ask: 100}}" }},
		{"ask", func(v int) string { return "{thresholds: {allow: 1, ask: " + strconv.Itoa(v) + "}}" }},
	} {
		bounds, ok := th.Properties[tc.key]
		if !ok {
			t.Fatalf("schema has no thresholds.%s", tc.key)
		}
		for v := -1; v <= 101; v++ {
			_, err := CompileGateConfig(gateContract(t, tc.pair(v)))
			if schema := v >= bounds.Minimum && v <= bounds.Maximum; schema != (err == nil) {
				t.Errorf("thresholds.%s %d: the schema (%d..%d) accepts %t, compile accepts %t (%v)",
					tc.key, v, bounds.Minimum, bounds.Maximum, schema, err == nil, err)
			}
		}
		// The loader's schema tree reports the same range for an out-of-range value.
		f := newFixture(t)
		path := filepath.Join(f.project, "agent.yaml")
		f.file(path, "version: 0\nname: t\ncommand: [\"python\"]\ngate:\n  thresholds: {"+tc.key+": 0}\n", 0o644)
		_, ds, err := Load(path, f.profiles())
		want := "gate " + tc.key + " threshold must be between " + strconv.Itoa(bounds.Minimum) + " and " + strconv.Itoa(bounds.Maximum)
		if err == nil || !strings.Contains(render(ds), want) {
			t.Errorf("load of %s 0: err %v, diagnostics lack %q:\n%s", tc.key, err, want, render(ds))
		}
	}
}
