// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
)

func TestScanSettingsEveryOutputChannel(t *testing.T) {
	const canary = "MCP_CANARY_18"
	o, _ := fixtureScanCommand(t)
	for _, tc := range []struct{ name, content string }{
		{".mcp.json", `{"mcpServers":{"local":{"command":"/secret/MCP_CANARY_18/codex","args":["--token","MCP_CANARY_18","--header=MCP_CANARY_18"],"env":{"TOKEN":"MCP_CANARY_18","nested":{"key":"MCP_CANARY_18"}},"headers":{"Authorization":"MCP_CANARY_18"}},"remote":{"url":"https://user:MCP_CANARY_18@example.invalid/MCP_CANARY_18?MCP_CANARY_18"}}}`},
		{".codex/config.toml", "[mcp_servers.local]\ncommand='codex'\nargs=['--token','MCP_CANARY_18']\nenv={TOKEN='MCP_CANARY_18'}\nheaders={Authorization='MCP_CANARY_18'}\n[mcp_servers.remote]\nurl='https://user:MCP_CANARY_18@example.invalid/MCP_CANARY_18?MCP_CANARY_18'\n"},
		{".config/systemd/user/codex.service", "[Service]\nEnvironment=TOKEN=MCP_CANARY_18\nExecStart=-@:/usr/bin/node alias /opt/MCP_CANARY_18/@openai/codex/bin/codex.js --token MCP_CANARY_18 %h\n"},
	} {
		p := filepath.Join(o.Directory, tc.name)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		writeTestFile(t, p, tc.content)
	}
	cache := filepath.Join(o.Directory, ".tego/scan/last.json")
	for _, args := range [][]string{nil, {"--verbose"}, {"--json"}, {"--all-mine", "-v"}, {"--check"}, {"--json", "--check"}} {
		code, out, errs := run(t, append([]string{"scan"}, args...)...)
		want := 0
		if strings.Contains(strings.Join(args, " "), "--check") {
			want = 1
		}
		if code != want {
			t.Fatalf("exit %d: %s", code, errs)
		}
		saved, e := os.ReadFile(cache)
		if e != nil {
			t.Fatal(e)
		}
		channels := []string{out, errs, string(saved)}
		log, e := os.ReadFile(filepath.Join(testHome, ".tego/tego.log"))
		if e != nil && !os.IsNotExist(e) {
			t.Fatal(e)
		}
		channels = append(channels, string(log))
		for _, s := range channels {
			if strings.Contains(s, canary) {
				t.Fatal("canary in stdout, stderr, saved result or own log")
			}
		}
		s, e := result.Decode(saved)
		if e != nil {
			t.Fatal(e)
		}
		if s.Counts.MCP < 4 || s.Counts.Units != 1 {
			t.Fatalf("missing configured rows %+v", s.Counts)
		}
		var wire any
		if e = json.Unmarshal(saved, &wire); e != nil {
			t.Fatal(e)
		}
		if e = jsonschema.Check("../../spec/scan/v1/schema.json", wire); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range []string{`{"mcpServers":{"s":{"args":[{"token":"MCP_CANARY_18"}]}}}`, `{"mcpServers":{"s":{"command":"codex","command":"MCP_CANARY_18"}}}`, `{"mcpServers":{"s":{"url":{"token":"MCP_CANARY_18"}}}}`} {
		writeTestFile(t, filepath.Join(o.Directory, ".mcp.json"), bad)
		_, out, errs := run(t, "scan", "--json")
		if strings.Contains(out+errs, canary) {
			t.Fatal("canary in refusal output")
		}
		s, e := result.Decode([]byte(out))
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, p := range s.Sources {
			found = found || p.Kind == "D" && p.State == "not-read"
		}
		if !found {
			t.Fatal("malformed settings not disclosed")
		}
	}
}
