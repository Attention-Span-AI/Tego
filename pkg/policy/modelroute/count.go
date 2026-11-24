// SPDX-License-Identifier: Apache-2.0

package modelroute

import (
	"encoding/json"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// RouteKey is what an ssl_request line says of the route it took: the host it named (canonical), the provider's
// endpoint it declared, and the route by name and backend. It is the whole of a line a request count reads, so a
// reader that has folded a run's lines into counts of RouteKey (the dashboard's read model does, once, as it reads
// the lines) can answer for any models[] list afterwards (CountsOf) without walking the ledger again.
type RouteKey struct{ Host, Provider, Route, Backend string }

// KeyOfPayload is the RouteKey of an ssl_request line's payload. routed is false for a request that took no route (a
// host no models[] entry declares routes for); err is a payload that does not decode as an ssl_request's.
func KeyOfPayload(payload []byte) (key RouteKey, routed bool, err error) {
	var p record.SSLRequestPayload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return RouteKey{}, false, err
	}
	if p.Route == nil {
		return RouteKey{}, false, nil
	}
	return RouteKey{agent.CanonicalHost(p.Host), p.Endpoint, p.Route.Name, p.Route.Authority}, true, nil
}

// endpoints maps each RouteKey a models[] list declares to the endpoint (host:port) it counts for.
func endpoints(ms []agent.ModelEndpoint) map[RouteKey]string {
	by := map[RouteKey]string{}
	for _, m := range ms {
		if m.Port == 0 {
			m.Port = 443
		}
		auth, host := m.ModelAuthority(), agent.CanonicalHost(m.Host)
		add := func(route, backend string) {
			k := RouteKey{host, m.Provider, route, backend}
			if _, dup := by[k]; !dup {
				by[k] = auth
			}
		}
		add(Direct, auth)
		for _, r := range m.Routes {
			add(r.Name, r.Authority())
		}
	}
	return by
}

// RequestCounter is a function that adds one ssl_request line of an endpoint that declares routes to counts, keyed by
// (endpoint, route): the per-route request counts of `tego route list`, which walks the run's ledger once and hands it
// every line (the dashboard's Model routes page counts the same from the read model's RouteKey counts, CountsOf). ms
// are the run's models[] entries.
//
// The endpoint is read off the line itself: its declared host and provider, and the route it took by name and
// backend, are matched to the models[] entry of that host and provider declaring that route (for direct, the backend
// is the entry's own authority). Two entries that declare the same route are therefore told apart by their host or
// provider; a line no entry matches is left out rather than counted against another endpoint.
func RequestCounter(ms []agent.ModelEndpoint) func(*record.Event, map[[2]string]int) {
	by := endpoints(ms)
	return func(e *record.Event, counts map[[2]string]int) {
		if e.Kind != record.KindSSLRequest {
			return
		}
		key, routed, err := KeyOfPayload(e.Payload)
		if err != nil || !routed {
			return
		}
		if ep, ok := by[key]; ok {
			counts[[2]string{ep, key.Route}]++
		}
	}
}

// CountsOf is RequestCounter's counts for the lines a tally holds: tally says how many ssl_request lines took each
// RouteKey, and the counts are those of every line RequestCounter(ms) would have counted, keyed the same.
func CountsOf(ms []agent.ModelEndpoint, tally map[RouteKey]int) map[[2]string]int {
	by := endpoints(ms)
	out := map[[2]string]int{}
	for key, n := range tally {
		if ep, ok := by[key]; ok {
			out[[2]string{ep, key.Route}] += n
		}
	}
	return out
}
