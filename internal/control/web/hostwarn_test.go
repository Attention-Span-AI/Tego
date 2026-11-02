// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// failHosts is a resolver that fails the names it holds (no such host) and resolves every other one.
type failHosts map[string]bool

func (f failHosts) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if f[host] {
		return nil, &net.DNSError{Err: "no such host", Name: host, Server: "127.0.0.53:53", IsNotFound: true}
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

const hostWarnHead = "Does not resolve here"

// TestPreviewSaysUnresolvedHost: the Change rules preview names each host the change adds that does not resolve here,
// with why, and what the next run does about it; Save is still offered, since it is a warning, not a refusal.
func TestPreviewSaysUnresolvedHost(t *testing.T) {
	plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: "/p/agent.yaml", Agent: "demo", Base: "b2", Direction: "widens",
		NeedsAck: true, Ack: "a1", Summary: "net.allow += api.exmple.com:443", Diff: "+    - api.exmple.com:443\n",
		Sentences:  []rules.Sentence{{After: "Can connect to api.exmple.com:443", Direction: "widens"}},
		Unresolved: []rules.UnresolvedHost{{Host: "api.exmple.com", Why: "no such host"}}}
	s, err := New(Config{Ledger: t.TempDir(), Port: port, Token: "tok123", Rules: &fakeChange{plan: plan}})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	body := do(s, "GET", "/rules/change/preview?c=00112233aabbccdd&base=b2&op=add&key=net.allow&v=api.exmple.com:443",
		"127.0.0.1:8484", c).Body.String()
	mustContain(t, "the preview", body, hostWarnHead, `<span class="mono">api.exmple.com</span> (no such host)`,
		"The next run looks it up when it starts and does not start while it fails", "Save the wider rules")
	plan.Unresolved = nil
	body = do(s, "GET", "/rules/change/preview?c=00112233aabbccdd&base=b2&op=add&key=net.allow&v=api.exmple.com:443",
		"127.0.0.1:8484", c).Body.String()
	if strings.Contains(body, hostWarnHead) {
		t.Error("a preview with every host resolved warns")
	}
}

// TestRawCheckSaysUnresolvedHost: the YAML editor's Check of a text that adds a host that does not resolve here says
// it compiles, and warns of the host.
func TestRawCheckSaysUnresolvedHost(t *testing.T) {
	f := newChangeFix(t)
	f.svc.Resolver = failHosts{"api.exmple.com": true}
	ref := f.ref(t, f.other)
	before := readText(t, f.other)
	check := func(text string) string {
		t.Helper()
		code, body := f.post(t, "/rules/change", url.Values{"mode": {"raw"}, "c": {ref.Ref}, "base": {ref.Base}, "step": {"check"},
			"text": {text}})
		if code != http.StatusOK || !strings.Contains(body, "It compiles") {
			t.Fatalf("check: %d", code)
		}
		return body
	}
	body := check(before + "net:\n  allow: [\"api.example.com:443\", \"api.exmple.com:443\"]\n")
	mustContain(t, "the check", body, hostWarnHead, `<span class="mono">api.exmple.com</span> (no such host)`)
	if strings.Contains(body, `<span class="mono">api.example.com</span>`) {
		t.Error("a host that resolves is named")
	}
	if body = check(before + "net:\n  allow: [\"api.example.com:443\"]\n"); strings.Contains(body, hostWarnHead) {
		t.Error("a text whose hosts all resolve warns")
	}
	if readText(t, f.other) != before {
		t.Error("Check wrote the file")
	}
}

// TestActCheckSaysUnresolvedHost: step 3 of the event page's "Act on this" warns of a host the picked change adds that
// does not resolve here, and still offers the confirm.
func TestActCheckSaysUnresolvedHost(t *testing.T) {
	s, c, _, _ := askServer(t)
	s.cfg.Rules.(*rules.Service).Resolver = failHosts{"api.example.com": true}
	page := do(s, "GET", "/runs/"+actRun+"/lines/5?a=ask", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the ask preview", page, "Check the change", hostWarnHead,
		`<span class="mono">api.example.com</span> (no such host)`, `id="act-confirm"`)
}
