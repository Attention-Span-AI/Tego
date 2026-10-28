// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/modelroutes"
)

const routesRun = "r-aaaaaaaa-0000000000005-routes"

// routesLiveFixture adds to fixture's root a live run whose anthropic endpoint declares two routes and is on corp now,
// with requests by direct and by corp, two change lines and an endpoint without routes.
func routesLiveFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	// The fixture's own waiting ask is answered, so no waiting banner sits over the page's heading.
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "answer", `"ask_id":"ask-7","approved":false,"by":"timeout","after_s":30`))
	dir := filepath.Join(root, routesRun)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	contract := `version: 0
name: routed-agent
command: [python3, agent.py]
capture: forwarder
models:
  - provider: anthropic
    host: api.anthropic.com
    port: 443
    routes:
      - {name: corp-proxy, host: llm-proxy.corp.example, port: 8443}
      - {name: local, host: 127.0.0.1, port: 11434, tls: false}
  - {provider: openai, host: api.openai.com, port: 443}
`
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-3 * time.Minute)
	fwd := func(seq int, kind, extra string) string {
		return strings.Replace(line(routesRun, "routed-agent", seq, t0.Add(time.Duration(seq)*10*time.Second), kind, extra), `"source":"supervisor"`, `"source":"forwarder"`, 1)
	}
	req := func(seq int, route, auth string) string {
		return fwd(seq, "ssl_request", `"endpoint":"anthropic","method":"POST","path":"/v1/messages","host":"api.anthropic.com","size":120,"route":{"name":"`+route+`","authority":"`+auth+`"}`)
	}
	change := func(seq int, route, auth string, serial int) string {
		return fwd(seq, "gap", `"what":"enforce","why":"model-route-changed","model_route":{"model":"api.anthropic.com:443","route":"`+route+`","authority":"`+auth+`","by":"uid:1000 pid:4242 dashboard","serial":`+strconv.Itoa(serial)+`,"at":"`+t0.Add(time.Duration(seq)*10*time.Second).UTC().Format(time.RFC3339)+`"}`)
	}
	ls := []string{
		line(routesRun, "routed-agent", 0, t0, "run_start", `"tier":"landlock","record_minor":27,"command":["python3","agent.py"]`),
		req(1, "direct", "api.anthropic.com:443"),
		req(2, "direct", "api.anthropic.com:443"),
		change(3, "local", "127.0.0.1:11434", 1),
		req(4, "local", "127.0.0.1:11434"),
		change(5, "corp-proxy", "llm-proxy.corp.example:8443", 2),
		req(6, "corp-proxy", "llm-proxy.corp.example:8443"),
		req(7, "corp-proxy", "llm-proxy.corp.example:8443"),
		req(8, "corp-proxy", "llm-proxy.corp.example:8443"),
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(ls, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", routesRun), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	o := modelroutes.New(routesRun)
	at := t0.Add(30 * time.Second)
	if _, err := o.Set("api.anthropic.com:443", "local", "uid:1000 pid:4242 dashboard", at); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Set("api.anthropic.com:443", "corp-proxy", "uid:1000 pid:4242 dashboard", at.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, modelroutes.FileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	holdLock(t, dir)
	return root
}

// TestModelRoutesInChrome renders the Model routes page and its preview at 1920x1080 and 390x844, light and dark: no
// horizontal scroll, no failed resource, no console or CSP error. With TEGO_CHROME_SHOTS set it saves each as
// routes-<page>-<width>-<scheme>.png there.
func TestModelRoutesInChrome(t *testing.T) {
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	root := routesLiveFixture(t)
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
		{"page", "/routes?t=tok123&run=" + routesRun, "Back to direct"},
		{"preview", "/routes/preview?t=tok123&run=" + routesRun + "&endpoint=api.anthropic.com:443&route=local", "Check this change"},
	}
	for _, p := range pages {
		for _, size := range [][2]int{{1920, 1080}, {390, 844}} {
			for _, scheme := range []string{"light", "dark"} {
				name := "routes-" + p.name + "-" + map[int]string{1920: "1920", 390: "390"}[size[0]] + "-" + scheme
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
