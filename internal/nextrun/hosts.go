// SPDX-License-Identifier: Apache-2.0

package nextrun

import (
	"context"
	"errors"
	"net"
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
	hosts := hostsOf(added)
	if len(hosts) == 0 {
		return nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	lookups, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var mu sync.Mutex
	errs := make([]error, len(hosts))
	answered := make([]bool, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Go(func() {
			ips, err := r.LookupNetIP(lookups, "ip", h)
			if err == nil && len(ips) == 0 {
				err = errNoAddresses
			}
			mu.Lock()
			errs[i], answered[i] = err, true
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
	if ctx.Err() != nil {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	var out []Unresolved
	for i, h := range hosts {
		switch {
		case !answered[i]:
			out = append(out, Unresolved{Host: h, Why: "no answer within " + budget.String()})
		case errs[i] != nil:
			out = append(out, Unresolved{Host: h, Why: why(errs[i], budget)})
		}
	}
	return out
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
