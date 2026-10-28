// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// TestLeastPrivilegeWithholdsTheLeak (QA PW-1): the Least privilege tab of a run that leaked says so in red, and its
// proposal, on the page and in the Download, never allows the address the secrets went to; the enforced run's tab
// is as it was. "Set up a new agent" from that run drafts the same: the sink is left out and a red notice says why.
func TestLeastPrivilegeWithholdsTheLeak(t *testing.T) {
	root := sysFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	const sink = "127.0.0.1:48802"
	allowed := `- "tcp://` + sink + `"`

	page := get(t, s, c, "/runs/"+sysWatchRun+"/least-privilege")
	for _, want := range []string{
		`class="banner banner-danger lp-leak" role="alert"`,
		"This run leaked secrets: id_ed25519, token sent to " + sink + ".",
		`The proposal below leaves <span class="mono">` + sink + `</span> out: a contract made from this run must never allow where its secrets went.`,
		"NOT allowed: " + html.EscapeString(`"tcp://`+sink+`"`),
		"# WARNING: secrets may have gone to " + sink,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the leak's Least privilege tab lacks %q", want)
		}
	}
	if strings.Contains(page, html.EscapeString(allowed)) || strings.Contains(page, allowed) {
		t.Error("the leak's proposal still allows the sink")
	}
	pre := page[strings.Index(page, `<pre class="mono lp-contract">`)+len(`<pre class="mono lp-contract">`):]
	pre = html.UnescapeString(pre[:strings.Index(pre, "</pre>")])

	w := do(s, "GET", "/runs/"+sysWatchRun+"/least-privilege.yaml", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("download: %d %s", w.Code, w.Body)
	}
	if dl := w.Body.String(); dl != pre {
		t.Errorf("the Download is not the text the tab shows:\n%s\n---\n%s", dl, pre)
	}

	// The cache's value is shared: a second view withholds again from the same text, never twice.
	if again := get(t, s, c, "/runs/"+sysWatchRun+"/least-privilege"); strings.Count(again, "# WARNING:") != 1 {
		t.Error("a second view warns more than once: the shared proposal was modified")
	}

	guard := get(t, s, c, "/runs/"+sysGuardRun+"/least-privilege")
	if strings.Contains(guard, "lp-leak") || strings.Contains(guard, "NOT allowed") || strings.Contains(guard, "WARNING: this run leaked") {
		t.Error("the protected run's tab is changed")
	}

	// "Set up a new agent" from the leaked run.
	home := t.TempDir()
	dir := filepath.Join(home, "proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.cfg.Setup = &rules.Service{Ledger: root, Home: home, Compile: func(context.Context, rules.CheckContext, []byte) error { return nil }}
	q := url.Values{"mode": {"run"}, "from": {sysWatchRun}, "dir": {dir}, "name": {"learned"}, "preview": {"1"}}
	prev := get(t, s, c, "/rules/new?"+q.Encode())
	for _, want := range []string{
		"leaked to " + sink + "</strong>", "Left out: ",
		"run " + sysWatchRun + " leaked secrets to " + sink + ": that address is left out of the proposal",
		"NOT allowed: " + html.EscapeString(`"tcp://`+sink+`"`),
	} {
		if !strings.Contains(prev, want) {
			t.Errorf("the preview from the leaked run lacks %q", want)
		}
	}
	if strings.Contains(prev, html.EscapeString(allowed)) || strings.Contains(prev, "Can connect to 127.0.0.1 on port 48802") {
		t.Error("the preview from the leaked run allows the sink")
	}
	q.Set("from", sysGuardRun)
	if g := get(t, s, c, "/rules/new?"+q.Encode()); strings.Contains(g, "leaked secrets to") {
		t.Error("the preview from the protected run warns of a leak")
	}
}
