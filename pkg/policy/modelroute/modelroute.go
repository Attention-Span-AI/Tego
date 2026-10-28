// SPDX-License-Identifier: Apache-2.0

package modelroute

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Direct is the route of the endpoint itself.
const Direct = agent.DirectRoute

// Route is where one endpoint's requests go: the route's name, its backend and whether the forwarder speaks TLS to it.
type Route struct {
	Name string
	Host string
	Port int
	TLS  bool
}

// Authority is the backend, host:port in the contract's canonical spelling.
func (r Route) Authority() string {
	return agent.ModelRoute{Host: r.Host, Port: r.Port}.Authority()
}

// IsDirect reports whether r is the endpoint itself.
func (r Route) IsDirect() bool { return r.Name == Direct }

// Taken is r as a request line records it.
func (r Route) Taken() *record.RouteTaken {
	return &record.RouteTaken{Name: r.Name, Authority: r.Authority()}
}

// DirectOf is m's own endpoint as a route: TLS to the declared host, port 443 when it names none.
func DirectOf(m agent.ModelEndpoint) Route {
	port := m.Port
	if port == 0 {
		port = 443
	}
	return Route{Name: Direct, Host: agent.CanonicalHost(m.Host), Port: port, TLS: true}
}

// Resolve is where m's requests go while live is the route in force for it: "" and Direct are the endpoint itself, a
// declared route is that route, and any other name (an overlay naming a route this contract does not declare) is the
// endpoint itself with ok false, so a bad overlay never sends a request anywhere the contract did not name.
func Resolve(m agent.ModelEndpoint, live string) (r Route, ok bool) {
	if live == "" || live == Direct {
		return DirectOf(m), true
	}
	d, found := m.Route(live)
	if !found {
		return DirectOf(m), false
	}
	return Route{Name: d.Name, Host: agent.CanonicalHost(d.Host), Port: d.Port, TLS: d.UsesTLS()}, true
}

// Names are the routes a person may choose for m: Direct first, then the declared ones in contract order.
func Names(m agent.ModelEndpoint) []string {
	out := make([]string, 0, len(m.Routes)+1)
	out = append(out, Direct)
	for _, r := range m.Routes {
		out = append(out, r.Name)
	}
	return out
}

// Widens reports whether moving an endpoint from route from to route to sends its requests somewhere the contract's
// own endpoint does not: every move to a route other than Direct, from any other route. Returning to Direct narrows,
// and staying where it is changes nothing. A widening needs the person's acknowledgement of its preview and is refused
// from inside a run; every change, widening or not, is refused from inside a run, since the agent never chooses a
// route.
func Widens(from, to string) bool {
	if to == "" {
		to = Direct
	}
	if from == "" {
		from = Direct
	}
	return to != Direct && to != from
}
