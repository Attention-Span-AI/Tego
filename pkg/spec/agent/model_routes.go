// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
)

// DirectRoute is the name of a models[] entry's own endpoint as a route: the one every run starts on, and the one a
// person reverts to (ADR 0127). No declared route may take it.
const DirectRoute = "direct"

// ModelRoute is one models[].routes entry (agent-contract.md R32, ADR 0127): a backend a person may send that endpoint's
// requests to while the run lives, from `tego route set` or the dashboard's Model routes page. Only declared routes
// can be chosen, and the agent never chooses one: it keeps calling the same forwarder URL.
type ModelRoute struct {
	Name string `yaml:"name"`
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// TLS is false for a plaintext backend, allowed only on a loopback host (a model server on this machine); nil and
	// true are TLS with the backend's certificate verified for Host.
	TLS *bool `yaml:"tls,omitempty"`
}

// UsesTLS reports whether the forwarder speaks TLS to the route's backend: every route but one that says tls: false.
func (r ModelRoute) UsesTLS() bool { return r.TLS == nil || *r.TLS }

// Authority is the route's backend, host:port in CanonicalHost's spelling: what a credential's allow entry names to
// let the key go there, and what a request line's route records.
func (r ModelRoute) Authority() string {
	return net.JoinHostPort(CanonicalHost(r.Host), strconv.Itoa(r.Port))
}

// Route is the declared route name, ok false when the entry declares none of that name. DirectRoute is not a declared
// route: it is the entry itself.
func (m ModelEndpoint) Route(name string) (ModelRoute, bool) {
	for _, r := range m.Routes {
		if r.Name == name {
			return r, true
		}
	}
	return ModelRoute{}, false
}

// RouteAuthorities are the authorities of the entry's declared routes, in declaration order, each once.
func (m ModelEndpoint) RouteAuthorities() []string {
	out := make([]string, 0, len(m.Routes))
	for _, r := range m.Routes {
		if a := r.Authority(); !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// loopbackHost reports whether host names this machine's loopback: the name localhost itself or a loopback address.
// Names under .localhost are not taken: a resolver that does not apply RFC 6761 (glibc without systemd-resolved) asks
// DNS for them. The forwarder also refuses a plaintext route's connection to any address off loopback (ADR 0127 §1).
func loopbackHost(host string) bool {
	h := CanonicalHost(host)
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}

// validateModelRoutes checks models[].routes against R32: a name of the credential name rule, not "direct" and unique
// in its entry; a backend that is not the entry's own endpoint and not declared twice; tls: false only on a loopback
// host; one models[] entry per endpoint that declares routes (a person switches an endpoint, not an entry); and an
// explicit capture: forwarder, the only capture that carries the request and so can send it elsewhere.
func validateModelRoutes(ds *diags, c *Contract) {
	routed := false
	for _, m := range c.Models {
		if len(m.Routes) > 0 {
			routed = true
			break
		}
	}
	if !routed {
		return
	}
	at := func(key string) Pos {
		if p, ok := c.origins[key]; ok {
			return p
		}
		return c.origins["models"]
	}
	if c.Capture != CaptureForwarder {
		ds.errorf(at("models"), CodeContradiction, "models routes: need capture: forwarder: only Tego's forwarder carries a model request, so only it can send one to another backend").
			fix("write capture: forwarder")
	}
	byAuthority := map[string]int{}
	for i, m := range c.Models {
		key := "models." + strconv.Itoa(i)
		own := m.ModelAuthority()
		if first, dup := byAuthority[own]; dup && (len(m.Routes) > 0 || len(c.Models[first].Routes) > 0) {
			ds.errorf(at(key+".routes"), CodeContradiction, "models entries %d and %d are both %s, and one declares routes: a route switches an endpoint, so it needs one entry", first+1, i+1, own).
				fix("declare the endpoint once, with its routes")
		} else if !dup {
			byAuthority[own] = i
		}
		names := map[string]int{}
		backends := map[string]int{}
		for j, r := range m.Routes {
			rk := key + ".routes." + strconv.Itoa(j)
			switch {
			case !credentialNameRE.MatchString(r.Name):
				ds.errorf(at(rk+".name"), CodeSchema, "route name %q must match ^[a-z0-9-]{1,40}$", r.Name)
			case r.Name == DirectRoute:
				ds.errorf(at(rk+".name"), CodeSchema, "route name %q is the models[] entry's own endpoint", r.Name).
					fix("name the backend, for example corp-proxy or local")
			default:
				if first, dup := names[r.Name]; dup {
					ds.errorf(at(rk+".name"), CodeSchema, "route name %q already used by route %d of this entry", r.Name, first+1)
				} else {
					names[r.Name] = j
				}
			}
			if r.Port < 1 || r.Port > 65535 {
				continue // the schema refused it
			}
			auth := r.Authority()
			if first, dup := backends[auth]; auth == own {
				ds.errorf(at(rk+".host"), CodeContradiction, "route %q is the models[] endpoint %s itself, which is the direct route", r.Name, own).
					fix("remove the route; `tego route clear` sends requests there")
			} else if dup {
				ds.errorf(at(rk+".host"), CodeContradiction, "route %q reaches %s, as route %d does", r.Name, auth, first+1).
					fix("declare each backend once")
			} else {
				backends[auth] = j
			}
			if !r.UsesTLS() && !loopbackHost(r.Host) {
				ds.errorf(at(rk+".tls"), CodeContradiction, "route %q has tls: false to %s, which is not this machine: the prompts and any key would cross the network in the clear", r.Name, r.Host).
					fix("drop tls: false, or route to a model server on 127.0.0.1 or localhost")
			}
		}
	}
}

// modelRoutesTier refuses routes under `tego run --observe`, where nothing keeps the agent from writing the run's
// route overlay, and where the machine lowered capture below the forwarder (ADR 0127, as credentials).
func (k *compiler) modelRoutesTier() {
	routed := false
	for _, m := range k.c.Models {
		if len(m.Routes) > 0 {
			routed = true
			break
		}
	}
	if !routed {
		return
	}
	if k.o.observe {
		k.ds.errorf(k.pos("models"), CodeContradiction, "models routes: cannot run under --observe: nothing would keep the agent from choosing its own route").
			fix("run at an enforcing tier, without --observe")
	}
	if k.rt.Capture != CaptureForwarder && k.c.Capture == CaptureForwarder {
		k.ds.errorf(k.pos("capture"), CodeContradiction, "models routes: need the forwarder, and this machine runs capture %s", k.rt.Capture).
			fix("raise the machine's capture ceiling to forwarder")
	}
}
