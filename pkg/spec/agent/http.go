// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"

	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// CompileHTTPPolicy validates the listener scope and builds an immutable matcher.
// It also serves hand-built contracts; Load and Compile both call it.
func CompileHTTPPolicy(c *Contract) (*httppolicy.Policy, error) {
	if c == nil || c.Net == nil || len(c.Net.HTTP) == 0 {
		return nil, nil
	}
	if len(c.Net.HTTP) > httppolicy.MaxRules || len(c.Models) > httppolicy.MaxRules {
		return nil, fmt.Errorf("net.http exceeds %d rules or model listeners", httppolicy.MaxRules)
	}
	if c.Capture != CaptureForwarder {
		return nil, fmt.Errorf("net.http requires explicit capture: forwarder")
	}
	if len(c.Models) == 0 {
		return nil, fmt.Errorf("net.http requires declared models")
	}
	if backend.Tier(c.Tier) == backend.TierObserve {
		return nil, fmt.Errorf("net.http requires an enforcing tier")
	}
	models := map[string]int{}
	for _, m := range c.Models {
		if msg, _ := checkHost(m.Host); msg != "" {
			return nil, fmt.Errorf("net.http has invalid declared model host")
		}
		host := CanonicalHost(m.Host)
		port := m.Port
		if port == 0 {
			port = 443
		}
		if _, duplicate := models[host]; duplicate {
			return nil, fmt.Errorf("net.http cannot bind duplicate model host %q", host)
		}
		models[host] = port
	}
	rules := make([]httppolicy.Rule, 0, len(c.Net.HTTP))
	covered := map[string]bool{}
	for _, r := range c.Net.HTTP {
		if msg, _ := checkHost(r.Host); msg != "" {
			return nil, fmt.Errorf("net.http host must be a host name or address without a port or URL")
		}
		host := CanonicalHost(r.Host)
		port, ok := models[host]
		if !ok {
			return nil, fmt.Errorf("net.http host %q has no declared model listener", r.Host)
		}
		covered[host] = true
		rules = append(rules, httppolicy.Rule{Host: host, Port: port, Allow: r.Allow, Methods: r.Methods})
	}
	for host := range models {
		if !covered[host] {
			return nil, fmt.Errorf("net.http does not cover model listener %q", host)
		}
	}
	return httppolicy.Compile(rules)
}

func validateHTTP(ds *diags, c *Contract, at func(string) Pos) {
	if _, err := CompileHTTPPolicy(c); err != nil {
		ds.errorf(at("net.http"), CodeSchema, "%v", err)
	}
}

func (k *compiler) http() {
	p, err := CompileHTTPPolicy(k.c)
	if err != nil {
		k.ds.errorf(k.pos("net.http"), CodeSchema, "%v", err)
		return
	}
	if p != nil && (k.rt.Capture != CaptureForwarder || k.rt.Tier == backend.TierObserve) {
		k.ds.errorf(k.pos("net.http"), CodeUnenforced, "net.http requires an enforcing tier and forwarder capture after machine ceilings")
		return
	}
	k.rt.HTTP = p
}
