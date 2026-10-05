// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func compiledProtocols(t *testing.T, model agent.ModelEndpoint, p *agent.ProxyPolicy) *agent.CompiledProxyPolicy {
	t.Helper()
	c := &agent.Contract{Capture: agent.CaptureForwarder, Models: []agent.ModelEndpoint{model}, Net: &agent.NetSection{Proxy: p}}
	policy, err := agent.CompileProxyPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestHTTP2ActualTLSUpstreamPolicyAndStreamIsolation(t *testing.T) {
	var calls atomic.Int64
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/allowed" || r.Method != "POST" {
			t.Errorf("forbidden request reached upstream: %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("upstream"))
	}))
	defer up.Close()
	host, port := hostPort(t, up.Listener.Addr().String())
	model := agent.ModelEndpoint{Host: host, Port: port, Provider: "anthropic"}
	p := compiledProtocols(t, model, &agent.ProxyPolicy{HTTP2: true, MaxStreams: 2})
	hp := policyFor(t, host, port, []string{"/allowed"}, []string{"POST"})
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p, HTTPPolicy: hp, Transport: up.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	run := testRun
	run.CgroupID, run.Contract = id, &agent.RuleTable{Record: agent.RecordSummary, HTTP: hp, Proxy: p}
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	if !m.ProxyPolicyReady(p) || !m.HTTPPolicyReady(hp) {
		t.Fatal("started protocol policy not ready")
	}
	l := m.Listeners()[0]
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/allowed", 200}, {"POST", "/denied", 403}, {"GET", "/allowed", 403}, {"POST", "/allowed", 200},
	} {
		req, _ := http.NewRequest(tc.method, l.BaseURL()+tc.path, strings.NewReader("bounded body"))
		req.Host = "forged.example"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.ProtoMajor != 2 || resp.StatusCode != tc.status {
			t.Fatalf("%s %s: %s %d", tc.method, tc.path, resp.Proto, resp.StatusCode)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls=%d", calls.Load())
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if m.ProxyPolicyReady(p) {
		t.Fatal("stopped proxy still attested ready")
	}
	if len(sink.of(record.KindNet)) != 4 {
		t.Fatal("missing per-stream network policy decisions")
	}
}
