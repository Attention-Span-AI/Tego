// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestOpaqueProxyModelBudgetRefusalBeforeUpstream(t *testing.T) {
	model := agent.ModelEndpoint{Host: "api.example.com", Port: 443}
	p := compiledProtocols(t, model, &agent.ProxyPolicy{Connect: []string{"api.example.com:443"}, WebSocket: []agent.HTTPRule{{Host: model.Host, Allow: []string{"/socket"}}}})
	for _, limits := range []agent.ResolvedLimits{
		{Set: agent.BudgetTokens}, {Set: agent.BudgetCostUSD}, {Set: agent.BudgetRepeats}, {Tokens: 1},
	} {
		m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("opaque budget bypass reached upstream")
			return nil, nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		run := testRun
		run.Contract = &agent.RuleTable{Record: agent.RecordOff, Proxy: p, Limits: limits}
		sink := &fakeSink{}
		if err := m.Start(context.Background(), run, sink); err == nil || !strings.Contains(err.Error(), "cannot enforce model") {
			t.Fatalf("manager accepted incompatible budget: %v", err)
		}
		// An embedding caller can Bind/Serve a listener without Manager.Start.
		l := m.Listeners()[0]
		l.Bind(run, sink)
		for _, method := range []string{"CONNECT", "GET"} {
			r := httptest.NewRequest(method, "http://api.example.com/socket", nil)
			if method == "CONNECT" {
				r.RequestURI = "api.example.com:443"
			} else {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
			}
			w := httptest.NewRecorder()
			if !l.serveExtraProtocol(w, r, 123) || w.Code != http.StatusForbidden {
				t.Fatalf("direct listener budget bypass: %s status=%d", method, w.Code)
			}
		}
		l.emitq.flush(time.Second)
		if events := sink.of(record.KindNet); len(events) != 2 || events[0].Verdict != record.VerdictRefused || events[1].Verdict != record.VerdictRefused {
			t.Fatalf("record-off missing refusals: %+v", events)
		}
		if err := m.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}
