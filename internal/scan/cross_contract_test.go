// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
)

const configuredArgumentSchema = "../../spec/scan/v1/schema.json"

func TestConfiguredArgumentBoundsAgreeWithSchema(t *testing.T) {
	for _, tc := range []struct {
		kind      string
		arguments int
		accepted  bool
	}{
		{"unit", 129, true},
		{"unit", 256, true},
		{"unit", 257, false},
		{"mcp", 128, true},
		{"mcp", 129, false},
	} {
		t.Run(fmt.Sprintf("%s-%d", tc.kind, tc.arguments), func(t *testing.T) {
			o := commandOptions(t)
			path, kind := ".config/systemd/user/args.service", "E"
			content := "[Service]\nExecStart=codex" + strings.Repeat(" arg", tc.arguments) + "\n"
			if tc.kind == "mcp" {
				path, kind = ".mcp.json", "D"
				content = `{"mcpServers":{"args":{"command":"codex","args":[` + strings.TrimSuffix(strings.Repeat(`"arg",`, tc.arguments), ",") + `]}}}`
			}
			writeSettings(t, o.Directory, path, []byte(content))
			s := Collect(t.Context(), o).Snapshot
			want := 0
			if tc.accepted {
				want = 1
			}
			if tc.kind == "unit" && s.Counts.Units != want || tc.kind == "mcp" && s.Counts.MCP != want {
				t.Fatalf("argument bound changed observed count: %+v", s.Counts)
			}
			found := false
			for _, source := range s.Sources {
				if source.Kind == kind && source.Locator != nil && strings.HasSuffix(*source.Locator, "/"+path) {
					found = true
					if tc.accepted && source.State != "read" || !tc.accepted && (source.State != "not-read" || source.Reason != "limit") {
						t.Fatalf("argument source state: %+v", source)
					}
				}
			}
			if !found {
				t.Fatal("argument source was not accounted for")
			}
			for _, item := range s.Items {
				if item.Kind == "user_unit" && item.Unit().Arguments != tc.arguments || item.Kind == "mcp_server" && item.Config().Arguments != tc.arguments {
					t.Fatalf("argument count changed: %+v", item)
				}
			}
			wire, e := result.Encode(s)
			if e != nil {
				t.Fatal(e)
			}
			var decoded any
			if e = json.Unmarshal(wire, &decoded); e != nil {
				t.Fatal(e)
			}
			if e = jsonschema.Check(configuredArgumentSchema, decoded); e != nil {
				t.Fatalf("collected argument count violates published schema: %v", e)
			}
		})
	}
}
