// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// ProxyBounds are fixed resource ceilings owned by the compiled policy.
type ProxyBounds struct {
	MaxStreams                    uint32
	MaxTunnelBytes, MaxFrameBytes int64
	TunnelIdle, TunnelWall        time.Duration
}

// CompiledProxyPolicy exposes immutable protocol decisions for fixed listeners.
type CompiledProxyPolicy struct {
	http2     bool
	opaque    bool
	bounds    ProxyBounds
	websocket *httppolicy.Policy
	connect   map[string]string
	models    map[string]bool
}

func (p *CompiledProxyPolicy) HTTP2Enabled() bool { return p != nil && p.http2 }

// ValidateLimits refuses model budgets that an opaque protocol cannot meter.
// Resolved limits include machine ceilings and explicitly bounded zero values.
func (p *CompiledProxyPolicy) ValidateLimits(limits ResolvedLimits) error {
	if p != nil && p.opaque && (limits.Bounded(BudgetTokens) || limits.Bounded(BudgetCostUSD) || limits.Bounded(BudgetRepeats)) {
		return fmt.Errorf("net.proxy CONNECT and websocket grants cannot enforce model token, cost or repeat budgets")
	}
	return nil
}
func (p *CompiledProxyPolicy) Bounds() ProxyBounds {
	if p == nil {
		return ProxyBounds{}
	}
	return p.bounds
}
func (p *CompiledProxyPolicy) Covers(authority string) bool { return p != nil && p.models[authority] }
func (p *CompiledProxyPolicy) Authorities() []string {
	if p == nil {
		return nil
	}
	keys := make([]string, 0, len(p.models))
	for key := range p.models {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func (p *CompiledProxyPolicy) Connect(authority string) (string, bool) {
	if p == nil {
		return "unmatched", false
	}
	rule, ok := p.connect[authority]
	return rule, ok
}
func (p *CompiledProxyPolicy) WebSocket(authority, path string) (string, bool) {
	if p == nil {
		return "unmatched", false
	}
	rule, allowed, _ := p.websocket.Match(authority, "GET", path)
	return strings.Replace(rule, "net.http[", "net.proxy.websocket[", 1), allowed
}

// CompileProxyPolicy requires explicit forwarder capture and declared upstreams.
// CONNECT grants refer only to those fixed authorities, never an arbitrary relay.
func CompileProxyPolicy(c *Contract) (*CompiledProxyPolicy, error) {
	if c == nil || c.Net == nil || c.Net.Proxy == nil {
		return nil, nil
	}
	raw := c.Net.Proxy
	if len(raw.Connect) > 0 && len(c.Net.HTTP) > 0 {
		return nil, fmt.Errorf("net.proxy.connect cannot accompany net.http: an opaque tunnel cannot enforce HTTP method/path policy")
	}
	if c.Capture != CaptureForwarder || len(c.Models) == 0 || backend.Tier(c.Tier) == backend.TierObserve {
		return nil, fmt.Errorf("net.proxy requires declared models, explicit capture: forwarder and an enforcing tier")
	}
	if !raw.HTTP2 && len(raw.WebSocket) == 0 && len(raw.Connect) == 0 {
		return nil, fmt.Errorf("net.proxy must explicitly enable http2, websocket routes or CONNECT destinations")
	}
	if len(c.Models) > httppolicy.MaxRules || len(raw.Connect) > httppolicy.MaxRules || len(raw.WebSocket) > httppolicy.MaxRules {
		return nil, fmt.Errorf("net.proxy exceeds %d listeners or protocol rules", httppolicy.MaxRules)
	}
	p := &CompiledProxyPolicy{http2: raw.HTTP2, opaque: len(raw.Connect) > 0 || len(raw.WebSocket) > 0, connect: map[string]string{}, models: map[string]bool{},
		bounds: ProxyBounds{MaxStreams: 32, MaxTunnelBytes: 16 << 20, MaxFrameBytes: 1 << 20, TunnelIdle: 30 * time.Second, TunnelWall: 5 * time.Minute}}
	var declared ResolvedLimits
	if c.Limits.Tokens != nil {
		declared.Set |= BudgetTokens
	}
	if c.Limits.CostUSD != nil {
		declared.Set |= BudgetCostUSD
	}
	if c.Limits.Repeats != nil {
		declared.Set |= BudgetRepeats
	}
	if err := p.ValidateLimits(declared); err != nil {
		return nil, err
	}
	modelPorts := map[string]int{}
	for _, m := range c.Models {
		if msg, _ := checkHost(m.Host); msg != "" {
			return nil, fmt.Errorf("net.proxy has an invalid model host")
		}
		host, port := CanonicalHost(m.Host), m.Port
		if port == 0 {
			port = 443
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("net.proxy has an invalid model port")
		}
		authority := httppolicy.Authority(host, port)
		if p.models[authority] {
			return nil, fmt.Errorf("net.proxy has a duplicate model authority")
		}
		p.models[authority] = true
		if prior, exists := modelPorts[host]; exists && prior != port {
			return nil, fmt.Errorf("net.proxy websocket host is ambiguous across model ports")
		}
		modelPorts[host] = port
	}
	for i, authority := range raw.Connect {
		e, err := ParseEndpoint(authority)
		if err != nil || e.Kind != EndpointHost || e.Proto != ProtoInet || e.Port < 1 {
			return nil, fmt.Errorf("net.proxy.connect[%d] requires a model host:port authority", i)
		}
		key := httppolicy.Authority(CanonicalHost(e.Host), e.Port)
		if !p.models[key] {
			return nil, fmt.Errorf("net.proxy.connect[%d] has no declared model listener", i)
		}
		if _, exists := p.connect[key]; exists {
			return nil, fmt.Errorf("net.proxy.connect[%d] duplicates a destination", i)
		}
		p.connect[key] = fmt.Sprintf("net.proxy.connect[%d]", i)
	}
	var rules []httppolicy.Rule
	for i, r := range raw.WebSocket {
		host := CanonicalHost(r.Host)
		port, found := modelPorts[host]
		if !found {
			return nil, fmt.Errorf("net.proxy.websocket[%d] has no declared model listener", i)
		}
		for _, method := range r.Methods {
			if method != "GET" {
				return nil, fmt.Errorf("net.proxy.websocket methods must be GET")
			}
		}
		rules = append(rules, httppolicy.Rule{Host: host, Port: port, Allow: r.Allow, Methods: []string{"GET"}})
	}
	var err error
	if p.websocket, err = httppolicy.Compile(rules); err != nil {
		return nil, err
	}
	if raw.MaxStreams != 0 {
		p.bounds.MaxStreams = raw.MaxStreams
	}
	if p.bounds.MaxStreams > 128 {
		return nil, fmt.Errorf("net.proxy.max_streams must be between 1 and 128")
	}
	if raw.MaxStreams != 0 && !raw.HTTP2 {
		return nil, fmt.Errorf("net.proxy.max_streams requires http2: true")
	}
	if raw.MaxTunnelBytes != nil {
		p.bounds.MaxTunnelBytes = int64(*raw.MaxTunnelBytes)
	}
	if raw.MaxFrameBytes != nil {
		p.bounds.MaxFrameBytes = int64(*raw.MaxFrameBytes)
	}
	if raw.TunnelIdle != nil {
		p.bounds.TunnelIdle = time.Duration(*raw.TunnelIdle)
	}
	if raw.TunnelWall != nil {
		p.bounds.TunnelWall = time.Duration(*raw.TunnelWall)
	}
	if p.bounds.MaxTunnelBytes < 1 || p.bounds.MaxTunnelBytes > 16<<30 || p.bounds.MaxFrameBytes < 1 || p.bounds.MaxFrameBytes > 16<<20 {
		return nil, fmt.Errorf("net.proxy tunnel/frame byte ceilings must be positive and at most 16GiB/16MiB")
	}
	if p.bounds.TunnelIdle <= 0 || p.bounds.TunnelIdle > time.Hour || p.bounds.TunnelWall <= 0 || p.bounds.TunnelWall > 24*time.Hour || p.bounds.TunnelIdle > p.bounds.TunnelWall {
		return nil, fmt.Errorf("net.proxy requires 0 < tunnel_idle <= tunnel_wall <= 24h and tunnel_idle <= 1h")
	}
	if len(raw.WebSocket) == 0 && len(raw.Connect) == 0 && (raw.MaxTunnelBytes != nil || raw.MaxFrameBytes != nil || raw.TunnelIdle != nil || raw.TunnelWall != nil) {
		return nil, fmt.Errorf("net.proxy tunnel bounds require websocket or CONNECT grants")
	}
	if raw.MaxFrameBytes != nil && len(raw.WebSocket) == 0 {
		return nil, fmt.Errorf("net.proxy.max_frame_bytes requires websocket routes")
	}
	return p, nil
}

func validateProxyPolicy(ds *diags, c *Contract, at func(string) Pos) {
	if _, err := CompileProxyPolicy(c); err != nil {
		ds.errorf(at("net.proxy"), CodeSchema, "%v", err)
	}
}
func (k *compiler) proxyPolicy() {
	p, err := CompileProxyPolicy(k.c)
	if err != nil {
		k.ds.errorf(k.pos("net.proxy"), CodeSchema, "%v", err)
		return
	}
	if p != nil && (k.rt.Capture != CaptureForwarder || k.rt.Tier == backend.TierObserve) {
		k.ds.errorf(k.pos("net.proxy"), CodeUnenforced, "net.proxy requires forwarder capture and enforcement after machine ceilings")
		return
	}
	if err := p.ValidateLimits(k.rt.Limits); err != nil {
		k.ds.errorf(k.pos("net.proxy"), CodeUnenforced, "%v", err)
		return
	}
	k.rt.Proxy = p
}
