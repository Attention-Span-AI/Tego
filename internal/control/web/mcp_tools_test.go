// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/mcptools"
)

const mcpContract = `version: 0
name: demo-harm
command: [sh, agent.sh]
mcp:
  - name: files
    command: [python3, /opt/fake-mcp/server.py]
    tools:
      deny: [delete_file]
      ask: [write_file]
  - name: web
    url: http://127.0.0.1:9523/mcp
`

// mcpFixture is the harm fixture's live run with mcpContract as its contract copy, made Adjustable (ADR 0125), so its
// switches may loosen past the contract; lockedMCPFixture leaves it Locked.
func mcpFixture(t *testing.T) string {
	t.Helper()
	root := lockedMCPFixture(t)
	adjustableHarm(t, root)
	return root
}

// adjustableHarm makes the harm run's run_start an Adjustable run's at record minor 26, with an empty fence.
func adjustableHarm(t *testing.T, root string) {
	t.Helper()
	p := filepath.Join(root, harmRun, "events.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	const old = `"tier":"landlock","command":["sh","agent.sh"]`
	if !strings.Contains(string(b), old) {
		t.Fatalf("the harm run's run_start lacks %s", old)
	}
	b = []byte(strings.Replace(string(b), old, `"tier":"cgroup","command":["sh","agent.sh"],"record_minor":26,"live_mode":"adjustable",`+
		`"live_fence":{"sha256":"`+strings.Repeat("0", 64)+`","entries":[]}`, 1))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func lockedMCPFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, harmRun, "contract.yaml"), []byte(mcpContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mcptools.WriteSeen(filepath.Join(root, harmRun), mcptools.Seen{"files": {"read_file", "write_file", "delete_file"}}); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestMCPPageRendersWithoutBroker: the page lists the run's servers, says which is behind the relay, and with no
// broker (the run's run_start names no ask capability) offers no Ask.
func TestMCPPageRendersWithoutBroker(t *testing.T) {
	root := mcpFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	holdLock(t, filepath.Join(root, harmRun))
	body := get(t, s, c, "/mcp?run="+harmRun)
	for _, want := range []string{"MCP tools", "files", "s relay</span>", "Not relayed", "delete_file", "write_file",
		`value="ask" class="seg seg-ask" aria-pressed="true" disabled`, `value="deny" class="seg seg-deny" aria-pressed="true"`,
		"Ask is off", `href="/static/mcp.css"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

// TestMCPLooseningGoesToPreview: a loosening without its acknowledgement is sent to the preview, which carries one;
// a tightening applies at once.
func TestMCPLooseningGoesToPreview(t *testing.T) {
	root := mcpFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	holdLock(t, filepath.Join(root, harmRun))
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		r := govRequest("POST", path, form)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := post("/mcp/set", url.Values{"csrf": {s.csrf}, "run": {harmRun}, "server": {"files"}, "tool": {"delete_file"}, "decision": {"allow"}})
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/mcp/preview?") {
		t.Fatalf("loosening: %d %q", w.Code, w.Header().Get("Location"))
	}
	prev := get(t, s, c, w.Header().Get("Location"))
	if !strings.Contains(prev, "Check this change") || !strings.Contains(prev, `name="ack"`) {
		t.Fatalf("preview lacks its acknowledgement:\n%s", prev)
	}
	if _, err := mcptools.Read(filepath.Join(root, harmRun), harmRun); err == nil {
		t.Fatal("the loosening wrote before its confirmation")
	}
	w = post("/mcp/set", url.Values{"csrf": {s.csrf}, "run": {harmRun}, "server": {"files"}, "tool": {"read_file"}, "decision": {"deny"}})
	if w.Code != http.StatusSeeOther || strings.HasPrefix(w.Header().Get("Location"), "/mcp/preview") {
		t.Fatalf("tightening: %d %q", w.Code, w.Header().Get("Location"))
	}
	o, err := mcptools.Read(filepath.Join(root, harmRun), harmRun)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := o.Lookup("files", "read_file"); !ok || e.Decision != "deny" || !strings.HasSuffix(e.By, "dashboard") {
		t.Fatalf("overlay after the tightening %+v", o)
	}
}

// TestMCPGovernedPeerRefused: a POST to the MCP page from a socket made inside a run is refused before the page sees
// it, as every dashboard change is (governed.go).
func TestMCPGovernedPeerRefused(t *testing.T) {
	root := mcpFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	tree := newCgroupTree(t, 1000)
	s.governed = (&governedCheck{cgroupRoot: func() (string, error) { return tree.root, nil },
		socketCgroup: func(netip.AddrPort, netip.AddrPort) (uint64, error) { return inode(t, tree.scope), nil }}).refuse
	for _, path := range []string{"/mcp/set", "/mcp/reset"} {
		r := govRequest("POST", path, url.Values{"csrf": {s.csrf}, "run": {harmRun}, "server": {"files"}, "tool": {"delete_file"}, "decision": {"allow"}})
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s from inside a run: %d", path, w.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(root, harmRun, mcptools.FileName)); err == nil {
		t.Fatal("a governed POST wrote the overlay")
	}
}

// TestMCPLockedRunRefusesLoosening: on a Locked run (ADR 0126 §4) a switch past the contract is refused in the words a
// Locked lift gets, on the flash after the POST and on the preview, which offers no acknowledgement; nothing is
// written. A tightening still applies at once.
func TestMCPLockedRunRefusesLoosening(t *testing.T) {
	root := lockedMCPFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	holdLock(t, filepath.Join(root, harmRun))
	post := func(form url.Values) *httptest.ResponseRecorder {
		r := govRequest("POST", "/mcp/set", form)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	for _, ack := range []string{"", "forged"} {
		w := post(url.Values{"csrf": {s.csrf}, "run": {harmRun}, "server": {"files"}, "tool": {"delete_file"}, "decision": {"allow"}, "ack": {ack}})
		loc := w.Header().Get("Location")
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/mcp?run=") {
			t.Fatalf("loosening a Locked run (ack %q): %d %q", ack, w.Code, loc)
		}
		if body := html.UnescapeString(get(t, s, c, loc)); !strings.Contains(body, "Not done: "+lockedWords) {
			t.Fatalf("the flash lacks the Locked words:\n%s", body)
		}
	}
	// The preview says it as the flash does, offers no acknowledgement and no promise of one, and leads back.
	prev := html.UnescapeString(get(t, s, c, "/mcp/preview?"+url.Values{"run": {harmRun}, "server": {"files"}, "tool": {"delete_file"}, "decision": {"allow"}}.Encode()))
	if !strings.Contains(prev, "Not done: "+lockedWords) || strings.Contains(prev, `name="ack"`) ||
		strings.Contains(prev, "until you confirm") || !strings.Contains(prev, `href="/mcp?run=`+harmRun+`">Back to MCP tools</a>`) {
		t.Fatalf("the preview of a Locked run's loosening:\n%s", prev)
	}
	if _, err := os.Stat(filepath.Join(root, harmRun, mcptools.FileName)); err == nil {
		t.Fatal("a refused loosening wrote the overlay")
	}
	if w := post(url.Values{"csrf": {s.csrf}, "run": {harmRun}, "server": {"files"}, "tool": {"read_file"}, "decision": {"deny"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("tightening: %d", w.Code)
	}
	if o, err := mcptools.Read(filepath.Join(root, harmRun), harmRun); err != nil || len(o.Tools) != 1 {
		t.Fatalf("the tightening on a Locked run: %+v %v", o, err)
	}
}
