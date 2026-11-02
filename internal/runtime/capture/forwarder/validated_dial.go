// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

type dialContext func(context.Context, string, string) (net.Conn, error)

// validatedDial resolves the fixed declared authority, classifies that exact
// answer, then dials its literal address. TLS keeps the declared host's SNI and
// certificate verification; no second resolver can rebind between check/dial.
type validatedDial struct {
	model                   agent.ModelEndpoint
	rules                   agent.RuleTable
	lookup                  agent.Resolver
	dial                    dialContext
	sem                     chan struct{}
	hosts                   *hostaddr.Snapshot
	mu                      sync.Mutex
	initialized, publicOnly bool
}

func newValidatedDial(model agent.ModelEndpoint, denied []netip.Prefix, lookup agent.Resolver, dial dialContext, sem chan struct{}) *validatedDial {
	model.Host = agent.CanonicalHost(model.Host)
	if model.Port == 0 {
		model.Port = 443
	}
	if lookup == nil {
		lookup = net.DefaultResolver
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	if sem == nil {
		sem = make(chan struct{}, 8)
	}
	// hosts is this host's own addresses, which a model name never admits unless it is a localhost name (agent-contract
	// R18, as the supervisor's resolved-address check): the interfaces' and every address of a `local` route of the
	// local routing table, an AnyIP range's, since a name resolved into one reaches a server bound to all interfaces.
	return &validatedDial{model: model, rules: agent.RuleTable{DeniedResolved: slices.Clone(denied)}, lookup: lookup, dial: dial, sem: sem,
		hosts: hostaddr.NewWithLocalTable(net.InterfaceAddrs, hostaddr.ReadLocalTable, time.Now, time.Second)}
}

func (d *validatedDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || agent.CanonicalHost(host) != d.model.Host || port != strconv.Itoa(d.model.Port) || network != "tcp" {
		return nil, fmt.Errorf("forwarder: dial is outside declared model authority")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if literal, err := netip.ParseAddr(d.model.Host); err == nil {
		return d.dial(ctx, network, net.JoinHostPort(literal.String(), port))
	}
	select {
	case d.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	lookupCtx, stop := context.WithTimeout(ctx, agent.DefaultDNSTimeout)
	addresses, lookupErr := d.lookup.LookupNetIP(lookupCtx, "ip", d.model.Host)
	stop()
	<-d.sem
	if lookupErr != nil {
		return nil, fmt.Errorf("forwarder: model resolution failed: %w", lookupErr)
	}
	if len(addresses) == 0 || len(addresses) > 64 {
		return nil, fmt.Errorf("forwarder: model resolution has no address or exceeds 64-address bound")
	}
	// Establish the first usable answer's private/public baseline once. Later
	// public-to-private rebinding is denied even on concurrent connection dials.
	d.mu.Lock()
	rule := agent.NetRule{Host: d.model.Host, PublicAnswer: d.publicOnly}
	seen := map[netip.Addr]bool{}
	kept := make([]netip.Addr, 0, len(addresses))
	allPublic := true
	for _, a := range addresses {
		a = a.Unmap()
		if !a.IsValid() || a.Zone() != "" || seen[a] {
			continue
		}
		seen[a] = true
		if _, forbidden := d.rules.ResolvedDenied(rule, a); forbidden {
			continue
		}
		if !agent.LocalhostName(rule.Host) {
			if local, known := d.hosts.Has(a); local || !known {
				continue
			}
		}
		kept = append(kept, a)
		probe := rule
		probe.PublicAnswer = true
		if _, private := d.rules.ResolvedDenied(probe, a); private {
			allPublic = false
		}
	}
	if !d.initialized && len(kept) > 0 {
		d.initialized, d.publicOnly = true, allPublic
	}
	d.mu.Unlock()
	if len(kept) == 0 {
		return nil, fmt.Errorf("forwarder: all model addresses refused by resolved-address policy")
	}
	var failures []error
	for _, a := range kept {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := d.dial(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
	}
	return nil, fmt.Errorf("forwarder: validated model addresses could not connect: %w", failures[len(failures)-1])
}
