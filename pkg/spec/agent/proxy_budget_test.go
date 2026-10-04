// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestOpaqueProxyRefusesDeclaredAndInheritedModelBudgets(t *testing.T) {
	for _, protocol := range []string{"connect: ['api.example.com:443']", "websocket: [{host: api.example.com, allow: [/socket]}]"} {
		base := "version: 0\nname: proxy-budget\ncommand: [/bin/true]\ncapture: forwarder\nmodels: [{host: api.example.com, port: 443, provider: anthropic}]\nnet: {proxy: {" + protocol + "}}\n"
		for _, budget := range []string{"tokens: 1", "cost_usd: 0.0001", "repeats: 1"} {
			_, ds, err := LoadBytes("proxy-budget.yaml", []byte(base+"limits: {"+budget+"}\n"), nil)
			if err == nil || !strings.Contains(render(ds), "cannot enforce model") {
				t.Fatalf("declared %s with %s: err=%v diagnostics=%s", budget, protocol, err, render(ds))
			}
		}
		c, ds, err := LoadBytes("proxy-budget.yaml", []byte(base), nil)
		if err != nil {
			t.Fatalf("unbounded load: %v %s", err, render(ds))
		}
		for _, limits := range []Limits{{Tokens: new(int64)}, {CostUSD: new(float64)}, {Repeats: new(int)}} {
			copy := *c
			copy.Limits = limits
			if _, err := CompileProxyPolicy(&copy); err == nil {
				t.Fatal("embedding declaration accepted a bounded zero model budget")
			}
		}
		for _, machine := range []*config.Machine{
			{Limits: config.Limits{Tokens: zeroCeil[int64]()}},
			{Limits: config.Limits{CostUSD: zeroCeil[float64]()}},
			{Limits: config.Limits{Repeats: bounded(5)}},
		} {
			_, ds, err := Compile(c, machine, Offline(), WithMountInfo(""))
			if err == nil || !strings.Contains(render(ds), "cannot enforce model") {
				t.Fatalf("machine budget with %s: err=%v diagnostics=%s", protocol, err, render(ds))
			}
		}
	}
}

func TestHTTP2ModelBudgetsRemainMetered(t *testing.T) {
	c := &Contract{Capture: CaptureForwarder, Models: []ModelEndpoint{{Host: "api.example.com", Port: 443}}, Net: &NetSection{Proxy: &ProxyPolicy{HTTP2: true}}}
	p, err := CompileProxyPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateLimits(ResolvedLimits{Set: BudgetTokens | BudgetCostUSD | BudgetRepeats}); err != nil {
		t.Fatal(err)
	}
}
