// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A provider declared twice gets the variables of the entry declared first, on every call,
// and the later entry is logged as reached by nothing the run installs (E22). Vars used to key the map by
// variable name in declaration order, so the last entry silently took the variables from the first, which
// contradicted NewManager's own account of one base URL per entry.
func TestAProviderDeclaredTwiceKeepsItsFirstEntry(t *testing.T) {
	var logged bytes.Buffer
	m, err := NewManager([]agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com"},
		{Provider: "anthropic", Host: "gateway.example.com"},
		{Provider: "google", Host: "generativelanguage.googleapis.com"},
		{Provider: "gemini", Host: "gemini.example.com"},
	}, Options{Logger: slog.New(slog.NewTextHandler(&logged, nil))})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	ls := m.Listeners()
	for i := 0; i < 3; i++ {
		vars := m.Vars()
		if got := vars["ANTHROPIC_BASE_URL"]; got != ls[0].BaseURL() {
			t.Fatalf("ANTHROPIC_BASE_URL = %q, want the first anthropic entry's %q", got, ls[0].BaseURL())
		}
		if got := vars["GOOGLE_GEMINI_BASE_URL"]; got != ls[2].BaseURL() {
			t.Fatalf("GOOGLE_GEMINI_BASE_URL = %q, want the first entry to claim it, %q", got, ls[2].BaseURL())
		}
	}
	for _, shadowed := range []*Listener{ls[1], ls[3]} {
		if !strings.Contains(logged.String(), shadowed.BaseURL()) {
			t.Errorf("the entry at %s, which no variable names, was not logged:\n%s", shadowed.BaseURL(), logged.String())
		}
	}
	for _, named := range []*Listener{ls[0], ls[2]} {
		if strings.Contains(logged.String(), named.BaseURL()) {
			t.Errorf("the entry at %s, which the variables do name, was logged as shadowed", named.BaseURL())
		}
	}
}

// An OpenAI harness appends its endpoint to the API root, version included, so the
// variable carries /v1 and a call through it reaches the upstream at the path the API serves. Without it
// the SDK asked the forwarder for /chat/completions, which it forwards unchanged to a path the upstream
// answers 404.
func TestOpenAIVariablesCarryTheAPIRoot(t *testing.T) {
	paths := make(chan string, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.Listener.Addr().String())
	m, err := NewManager([]agent.ModelEndpoint{{Provider: "openai", Host: host, Port: port}},
		Options{Transport: up.Client().Transport})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	m.Listeners()[0].peers = anyPeer
	sink := &fakeSink{}
	if err := m.Start(context.Background(), testRun, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	vars := m.Vars()
	for _, name := range []string{"OPENAI_BASE_URL", "OPENAI_API_BASE"} {
		if got, want := vars[name], m.Listeners()[0].BaseURL()+"/v1"; got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// What the OpenAI SDKs do with the variable: base_url + "/chat/completions".
	resp, err := http.Post(vars["OPENAI_BASE_URL"]+"/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-5","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	sink.waitFor(t, record.KindSSLResponse, 1)
	if got := <-paths; got != "/v1/chat/completions" {
		t.Errorf("the upstream was asked for %q, want /v1/chat/completions", got)
	}
}
