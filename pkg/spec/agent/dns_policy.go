// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
)

// CompileDNSPolicy owns its settings and constructs the broker's query matcher.
// Query controls require broker mode; they cannot silently affect system DNS.
func CompileDNSPolicy(c *Contract) (DNSPolicy, *dnspolicy.Policy, error) {
	p := DNSPolicy{Mode: "system"}
	if c == nil || c.Net == nil || c.Net.DNS == nil {
		return p, nil, nil
	}
	p = *c.Net.DNS
	p.Allow, p.Types = slices.Clone(p.Allow), slices.Clone(p.Types)
	p.MaxStale, p.Cache = cloneNetworkValue(p.MaxStale), cloneNetworkValue(p.Cache)
	if p.Mode == "" {
		p.Mode = "system"
	}
	if p.Mode != "system" && p.Mode != "broker" && p.Mode != "off" {
		return p, nil, fmt.Errorf("net.dns.mode must be system, broker or off")
	}
	if p.MaxStale != nil && (*p.MaxStale < 0 || time.Duration(*p.MaxStale) > 24*time.Hour) {
		return p, nil, fmt.Errorf("net.dns.max_stale must be between 0s and 24h after TTL expiry")
	}
	if p.Mode != "broker" {
		if p.Allow != nil || p.Types != nil || p.MaxParallel != 0 || p.Cache != nil {
			return p, nil, fmt.Errorf("net.dns query allow/types, max_parallel and cache require mode: broker")
		}
		return p, nil, nil
	}
	if p.MaxParallel == 0 {
		p.MaxParallel = 8
	}
	if p.MaxParallel < 1 || p.MaxParallel > 16 {
		return p, nil, fmt.Errorf("net.dns.max_parallel must be between 1 and 16")
	}
	if p.Cache == nil {
		capacity := 128
		p.Cache = &capacity
	}
	if *p.Cache < 0 || *p.Cache > 512 {
		return p, nil, fmt.Errorf("net.dns.cache must be between 0 and 512")
	}
	queries, err := dnspolicy.Compile(p.Allow, p.Types)
	return p, queries, err
}

// SystemResolvers reports whether a run under s keeps R14's implicit resolver exception (supervisor R14,
// SEMANTICS §5): mode system, or unset, does; off and broker remove the agent's implicit transport to the
// machine resolvers (network-controls.md, "Cooperating DNS broker"). The run's resolver list
// (runtime runResolvers) and compile --test's (cli testEnv) both read it here, so a port-53 row cannot be
// answered net.resolver where the run refuses it (2026-10-05).
func (s DNSPolicy) SystemResolvers() bool {
	return s.Mode != "off" && s.Mode != "broker"
}

func cloneNetworkValue[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func validateDNSPolicy(ds *diags, c *Contract, at func(string) Pos) {
	if _, _, err := CompileDNSPolicy(c); err != nil {
		ds.errorf(at("net.dns"), CodeSchema, "%v", err)
	}
}

func (k *compiler) dnsPolicy() {
	p, queries, err := CompileDNSPolicy(k.c)
	if err != nil {
		k.ds.errorf(k.pos("net.dns"), CodeSchema, "%v", err)
		return
	}
	k.rt.DNS, k.rt.DNSQueries = p, queries
	if p.MaxStale == nil {
		return
	}
	for _, entries := range [][]NetRule{k.rt.Net, k.rt.NetAsk} {
		for i := range entries {
			r := &entries[i]
			if r.Static || r.Host == "" {
				continue
			}
			if r.ResolvedAt.IsZero() {
				// Missing DNS evidence is already expired, rather than a timeless grant.
				r.ExpiresAt = time.Unix(0, 1)
			} else {
				r.ExpiresAt = r.ResolvedAt.Add(r.TTL).Add(time.Duration(*p.MaxStale))
			}
		}
	}
}
