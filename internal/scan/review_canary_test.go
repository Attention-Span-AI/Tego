// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

func TestReviewCanariesEveryChannel(t *testing.T) {
	o := commandOptions(t)
	jsonFile := `{"MCP_CANARY_18":{"MCP_CANARY_18":1},` +
		`"projects":{"/p/MCP_CANARY_18":{"mcpServers":{"s1":{"command":"/home/u/MCP_CANARY_18/bin/codex","args":[],"env":{"MCP_CANARY_18":"x"},"cwd":"/MCP_CANARY_18"}},"MCP_CANARY_18":[1,true,null,{"k":"MCP_CANARY_18"}]}},` +
		`"mcpServers":{"s2":{"type":"http","url":"https://MCP_CANARY_18.example.invalid/\u004dCP_CANARY_18","headers":{"MCP_CANARY_18":"\u004dCP_CANARY_18"}},` +
		`"s3":{"command":"MCP_CANARY_18","args":["\u004dCP_CANARY_18","--api-key","MCP_CANARY_18"],"alwaysAllow":["MCP_CANARY_18"],"disabled":false,"timeout":5000},` +
		`"s4":{"type":"sse","url":"http://[::1]:80/MCP_CANARY_18","oauth":{"clientSecret":"MCP_CANARY_18"}}}}`
	tomlFile := "model = \"MCP_CANARY_18\"\n" +
		"[mcp_servers.s1]\ncommand = \"/opt/MCP_CANARY_18/codex\"\nargs = [\"-y\", \"MCP_CANARY_18\", 'MCP_CANARY_18']\n\"MCP_CANARY_18\" = \"x\"\nenabled = true\n" +
		"[mcp_servers.s1.env]\nMCP_CANARY_18 = \"\\u004dCP_CANARY_18\"\n" +
		"[mcp_servers.s2]\nurl = \"https://MCP_CANARY_18@h.invalid/MCP_CANARY_18\"\nstartup_timeout_sec = 20\n" +
		"[mcp_servers.s2.http_headers]\n\"X-MCP_CANARY_18\" = 'MCP_CANARY_18'\n" +
		"[profiles.MCP_CANARY_18]\nx = 1\n"
	unitFile := "[Unit]\nDescription=MCP_CANARY_18\n[X-MCP_CANARY_18]\nMCP_CANARY_18=MCP_CANARY_18\n[Service]\nEnvironment=\"TOKEN=MCP_CANARY_18\"\n" +
		"ExecStart=/opt/MCP_CANARY_18/bin/codex --api-key=MCP_CANARY_18 MCP_CANARY_18 \"\\x4dCP_CANARY_18\"\n"
	nodeUnit := "[Service]\nExecStart=/usr/bin/node /opt/@openai/codex/bin/codex.js MCP_CANARY_18 --key MCP_CANARY_18\n"
	timer := "[Timer]\nOnCalendar=daily\nUnit=c1.service\n"
	writeSettings(t, o.Directory, ".claude.json", []byte(jsonFile))
	writeSettings(t, o.Directory, ".codex/config.toml", []byte(tomlFile))
	writeSettings(t, o.Directory, ".config/systemd/user/c1.service", []byte(unitFile))
	writeSettings(t, o.Directory, ".config/systemd/user/c2.service", []byte(nodeUnit))
	writeSettings(t, o.Directory, ".config/systemd/user/c1.timer", []byte(timer))
	unitRoot := filepath.Join(o.Directory, ".config/systemd/user")
	for _, link := range []struct{ name, target string }{
		{"c1-alias.service", filepath.Join(unitRoot, mcpCanary, "c1.service")},
		{"outside-alias.service", filepath.Join(o.Directory, mcpCanary, "outside.service")},
	} {
		if e := os.Symlink(link.target, filepath.Join(unitRoot, link.name)); e != nil {
			t.Fatal(e)
		}
	}
	s := Collect(t.Context(), o).Snapshot
	for _, src := range s.Sources {
		if src.Kind == "D" || src.Kind == "E" {
			t.Logf("R6 source %s %s %s", *src.Locator, src.State, src.Reason)
		}
	}
	t.Logf("R6 counts mcp=%d units=%d", s.Counts.MCP, s.Counts.Units)
	assertNoCanary(t, s)
	b, e := result.Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte(mcpCanary)) {
		t.Fatal("R6 canary in JSON")
	}
	for _, j := range []bool{false, true} {
		for _, v := range []bool{false, true} {
			var out, errs bytes.Buffer
			_ = result.Render(&out, &errs, s, j, v, nil)
			if strings.Contains(out.String()+errs.String(), mcpCanary) {
				t.Fatal("R6 canary in render")
			}
			if !j && v {
				for _, line := range strings.Split(out.String(), "\n") {
					if strings.Contains(line, "MCP server") || strings.Contains(line, "User ") || strings.Contains(line, ": read;") {
						t.Logf("R6 text: %s", line)
					}
				}
			}
		}
	}
}
