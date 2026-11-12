// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/mcptools"
)

const mcpRun = "r-aaaaaaaa-0000000000004-mcpdem"

// mcpLiveFixture adds to fixture's root a live run with two MCP servers behind the relay, a mixed state (a contract
// deny, an ask, a live deny), the relay's lines and one held mcp_tool call on the broker.
func mcpLiveFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	// The fixture's own waiting ask is answered, so only this run's held call is waiting once it is asked.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "answer", `"ask_id":"ask-7","approved":false,"by":"timeout","after_s":30`))
	dir := filepath.Join(root, mcpRun)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	contract := `version: 0
name: mcp-demo
command: [python3, agent.py]
ask: {timeout: 2m}
mcp:
  - name: files
    command: [python3, /opt/fake-mcp/server.py]
    tools: {deny: [delete_file], ask: [write_file]}
  - name: web
    url: http://127.0.0.1:9523/mcp
    tools: {deny: [delete_file]}
  - name: notes
    command: [npx, -y, notes-mcp]
`
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-2 * time.Minute)
	proxy := func(seq int, extra string) string {
		return strings.Replace(line(mcpRun, "mcp-demo", seq, t0.Add(time.Duration(seq)*time.Second), "mcp", extra), `"source":"supervisor"`, `"source":"proxy"`, 1)
	}
	ls := []string{
		line(mcpRun, "mcp-demo", 0, t0, "run_start", `"tier":"cgroup","record_minor":26,"command":["python3","agent.py"],"capabilities":{"ask":true},"live_mode":"adjustable",`+
			`"live_fence":{"sha256":"`+strings.Repeat("0", 64)+`","entries":[]}`),
		proxy(1, `"rule":"mcp[files]","verdict":"allow","authority":"rule","name":"files","transport":"stdio","tool":"read_file"`),
		proxy(2, `"rule":"mcp[files]","verdict":"allow","authority":"rule","name":"files","transport":"stdio","tool":"read_file"`),
		proxy(3, `"rule":"mcp[files].tools.deny[delete_file]","verdict":"refused","authority":"rule","reason":"mcp-tool-denied","name":"files","transport":"stdio","tool":"delete_file"`),
		proxy(4, `"rule":"mcp[web]","verdict":"allow","authority":"rule","name":"web","transport":"http","tool":"read_file"`),
		proxy(5, `"rule":"mcp[web].live[read_file]","verdict":"refused","authority":"rule","reason":"mcp-tool-denied","name":"web","transport":"http","tool":"read_file"`),
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(ls, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", mcpRun), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mcptools.WriteSeen(dir, mcptools.Seen{"files": {"read_file", "write_file", "delete_file", "list_dir"}, "web": {"read_file", "delete_file", "search"}}); err != nil {
		t.Fatal(err)
	}
	o := mcptools.New(mcpRun)
	if _, err := o.Set("web", "read_file", mcptools.Deny, "uid:1000 pid:1 dashboard", time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, mcptools.FileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	holdLock(t, dir)
	return root
}

// TestMCPPagesInChrome renders the MCP tools page, its loosening preview and Approvals holding an mcp_tool ask at
// 1440x900 and 390x844, light and dark: no horizontal scroll, no console error, no CSP report. With
// TEGO_CHROME_SHOTS set it saves each as mcp-<page>-<size>-<scheme>.png there.
func TestMCPPagesInChrome(t *testing.T) {
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	root := mcpLiveFixture(t)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prof := os.Getenv("TEGO_CHROME_PROFILE")
	if prof == "" {
		prof = filepath.Join(t.TempDir(), "profile")
	}
	cmd := exec.Command(chrome, "--headless=new", "--remote-debugging-pipe", "--user-data-dir="+prof, "--no-first-run",
		"--no-default-browser-check", "--disable-gpu", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-component-update", "--enable-logging=stderr", "--v=0", "about:blank")
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = cmdR.Close()
	_ = outW.Close()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("chrome stderr:\n%s", stderr.String())
		}
	})
	c := &cdp{w: cmdW, wait: map[int]chan json.RawMessage{}}
	go c.read(outR)
	base := "http://" + addr
	shots := os.Getenv("TEGO_CHROME_SHOTS")
	pages := []struct{ name, path, want string }{
		{"tools", "/mcp?t=tok123&run=" + mcpRun, "Behind Tego"},
		{"preview", "/mcp/preview?t=tok123&run=" + mcpRun + "&server=files&tool=delete_file&decision=allow", "Check this change"},
		{"approvals", "/approvals?t=tok123", "call the MCP tool"},
	}
	for _, p := range pages {
		if p.name == "approvals" {
			// The held call is asked only now, so the pages before show no waiting banner over their heading.
			appendLine(t, root, mcpRun, line(mcpRun, "mcp-demo", 6, time.Now().Add(-5*time.Second), "ask", `"ask_id":"q-0123456789abcdef0123456789abcd01","hold":"request","op":"mcp_tool","target":"files write_file","ask_rule":"mcp[files].tools.ask[write_file]"`))
		}
		for _, size := range [][2]int{{1440, 900}, {390, 844}} {
			for _, scheme := range []string{"light", "dark"} {
				name := "mcp-" + p.name + "-" + map[int]string{1440: "1440", 390: "390"}[size[0]] + "-" + scheme
				tb := c.open(t, name, "about:blank")
				c.call(t, tb.session, "Runtime.enable", map[string]any{})
				c.call(t, tb.session, "Log.enable", map[string]any{})
				c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": size[0], "height": size[1], "deviceScaleFactor": 1, "mobile": size[0] < 500})
				c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": base + p.path})
				tb.until(t, "loaded", `document.readyState === "complete" && document.body.innerText.includes(`+mcpJS(p.want)+`)`)
				if over := tb.eval(t, `document.documentElement.scrollWidth > innerWidth`); over != "false" {
					t.Errorf("%s: horizontal scroll (scrollWidth %s, width %d)", name, tb.eval(t, `document.documentElement.scrollWidth`), size[0])
				}
				if errs := tb.eval(t, `JSON.stringify(performance.getEntriesByType("resource").filter(e => e.responseStatus >= 400).map(e => e.name))`); errs != `"[]"` {
					t.Errorf("%s: failed resources %s", name, errs)
				}
				if shots != "" {
					c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target})
					var r struct{ Data []byte }
					_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
					if err := os.WriteFile(filepath.Join(shots, name+".png"), r.Data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	if s := stderr.String(); strings.Contains(s, "Content Security Policy") || strings.Contains(s, "Refused to") || strings.Contains(s, "Uncaught") {
		t.Errorf("chrome reported a CSP or script error:\n%s", s)
	}
}

func mcpJS(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
