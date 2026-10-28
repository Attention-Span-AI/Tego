// SPDX-License-Identifier: Apache-2.0

package modelroute

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// RequestCounter is a function that adds one ssl_request line of an endpoint that declares routes to counts, keyed by
// (endpoint, route): the per-route request counts of the dashboard's Model routes page and `tego route list`, which
// each walk the run's ledger and hand it every line. ms are the run's models[] entries.
//
// The endpoint is read off the line itself: its declared host and provider, and the route it took by name and
// backend, are matched to the models[] entry of that host and provider declaring that route (for direct, the backend
// is the entry's own authority). Two entries that declare the same route are therefore told apart by their host or
// provider; a line no entry matches is left out rather than counted against another endpoint.
func RequestCounter(ms []agent.ModelEndpoint) func(*record.Event, map[[2]string]int) {
	type key struct{ host, provider, route, backend string }
	by := map[key]string{}
	for _, m := range ms {
		if m.Port == 0 {
			m.Port = 443
		}
		auth, host := m.ModelAuthority(), agent.CanonicalHost(m.Host)
		add := func(route, backend string) {
			k := key{host, m.Provider, route, backend}
			if _, dup := by[k]; !dup {
				by[k] = auth
			}
		}
		add(Direct, auth)
		for _, r := range m.Routes {
			add(r.Name, r.Authority())
		}
	}
	return func(e *record.Event, counts map[[2]string]int) {
		if e.Kind != record.KindSSLRequest {
			return
		}
		var p record.SSLRequestPayload
		if e.DecodePayload(&p) != nil || p.Route == nil {
			return
		}
		if ep, ok := by[key{agent.CanonicalHost(p.Host), p.Endpoint, p.Route.Name, p.Route.Authority}]; ok {
			counts[[2]string{ep, p.Route.Name}]++
		}
	}
}
