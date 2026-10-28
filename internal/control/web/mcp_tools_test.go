// SPDX-License-Identifier: Apache-2.0

package web

import (
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

func mcpFixture(t *testing.T) string {
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
