// SPDX-License-Identifier: Apache-2.0

package nextrun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// HostBudget is how long a rule write waits, at most, for the host names its change adds to resolve. They are looked
// up all at once, so a change waits this long only where DNS does not answer.
const HostBudget = 2 * time.Second

// maxHosts is how many host names one change has looked up: the compiler's own bound on lookups at once
// (agent.DefaultDNSParallel). Only a free edit adds more; the rest are not looked up here, and the next run's start
// resolves every one.
const maxHosts = agent.DefaultDNSParallel

// Unresolved is a host name a change adds that did not resolve here: a warning, never a refusal. Compile does no DNS
// (a host name is resolved at run start, E18), and the next run, unless started --offline, does not start while one of
// its hosts fails to resolve.
type Unresolved struct {
	Host string
	// Why is what the lookup said ("no such host", "no addresses"), or that it did not answer within the budget.
	Why string
}

// UnresolvedHosts looks up the host names of added, the net.allow and net.ask entries a change adds, through r (nil is
// the system's resolver), and returns those that did not resolve, in the order added names them. An entry that needs
// no DNS (a literal address, a CIDR, a unix socket) or does not parse (the compile refuses it) names none. The first
// maxHosts names are looked up, all at once, and it returns within budget whatever DNS does: a lookup that has not
// answered by then did not resolve here, and is left to end on its own (a resolver that honors its context ends it
// then). It returns nil when ctx ends first: the caller is gone, and no host is to blame.
func UnresolvedHosts(ctx context.Context, r agent.Resolver, added []string, budget time.Duration) []Unresolved {
	answers, err := LookupHosts(ctx, r, hostsOf(added), budget)
	if err != nil {
		return nil
	}
	var out []Unresolved
	for _, a := range answers {
		if a.Why != "" {
			out = append(out, Unresolved{Host: a.Host, Why: a.Why})
		}
	}
	return out
}

// Answer is what one host name resolves to here now, or why it does not.
type Answer struct {
	Host string
	// Addrs are the addresses of the answer, in the resolver's order, each once, an IPv4-mapped one as its IPv4
	// address; nil when Why is set.
	Addrs []netip.Addr
	// Why is what the lookup said ("no such host", "no addresses"), or that it did not answer within the budget; ""
	// when the name resolved.
	Why string
}

// LookupHosts looks every name of hosts up through r, all at once, and returns each one's answer in the order hosts
// gives them. nil r is net.DefaultResolver, the resolver Compile uses when a run starts (agent.Compile's default; tego
// run sets no other), with the network "ip" Compile asks for: so an answer is what the next run's start would see
// from here, now, and a machine config's resolver: setting, which names the servers the agent may send DNS to, changes
// neither. Every name is looked up, however many: the caller bounds them (tego learn takes at most
// agent.DefaultDNSParallel). It returns within budget whatever DNS does: a name that has not answered by then has Why
// "no answer within <budget>", and its lookup is left to end on its own. It returns ctx's error and no answer when
// ctx ends first.
func LookupHosts(ctx context.Context, r agent.Resolver, hosts []string, budget time.Duration) ([]Answer, error) {
	if len(hosts) == 0 {
		return nil, ctx.Err()
	}
	if r == nil {
		r = net.DefaultResolver
	}
	lookups, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var mu sync.Mutex
	out := make([]Answer, len(hosts))
	answered := make([]bool, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Go(func() {
			ips, err := r.LookupNetIP(lookups, "ip", h)
			a := Answer{Host: h}
			switch {
			case err != nil:
				a.Why = why(err, budget)
			case len(ips) == 0:
				a.Why = why(errNoAddresses, budget)
			default:
				for _, ip := range ips {
					if ip = ip.Unmap(); ip.IsValid() && !slices.Contains(a.Addrs, ip) {
						a.Addrs = append(a.Addrs, ip)
					}
				}
				if len(a.Addrs) == 0 {
					a.Why = why(errNoAddresses, budget)
				}
			}
			mu.Lock()
			out[i], answered[i] = a, true
			mu.Unlock()
		})
	}
	all := make(chan struct{})
	go func() {
		wg.Wait()
		close(all)
	}()
	select {
	case <-all:
	case <-lookups.Done():
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A copy: a lookup that answers after the budget still writes its slot of out, which the caller must not share.
	mu.Lock()
	defer mu.Unlock()
	res := make([]Answer, len(hosts))
	for i, h := range hosts {
		res[i] = out[i]
		if !answered[i] {
			res[i] = Answer{Host: h, Why: "no answer within " + budget.String()}
		}
	}
	return res, nil
}

// hostsOf is the host names entries name, each once, in order, at most maxHosts of them.
func hostsOf(entries []string) []string {
	var out []string
	for _, raw := range entries {
		e, err := agent.ParseEndpoint(raw)
		if err != nil || e.Static() || slices.Contains(out, e.Host) {
			continue
		}
		if len(out) == maxHosts {
			break
		}
		out = append(out, e.Host)
	}
	return out
}

var errNoAddresses = errors.New("no addresses")

// why is what a failed lookup said, short: DNS's own words without the server it asked ("no such host"), or that it
// did not answer within the budget.
func why(err error, budget time.Duration) string {
	var de *net.DNSError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &de) && de.IsTimeout:
		return "no answer within " + budget.String()
	case errors.As(err, &de) && de.IsNotFound:
		return "no such host"
	case errors.As(err, &de) && de.Err != "":
		return de.Err
	}
	return err.Error()
}
