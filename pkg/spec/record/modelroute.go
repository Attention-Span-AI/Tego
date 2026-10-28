// SPDX-License-Identifier: Apache-2.0

package record

import (
	jsonv2 "encoding/json/v2"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The fields MinorModelRoutes adds (ADR 0127).
const (
	routeKey      = "route"
	modelRouteKey = "model_route"
)

// GapModelRouteChanged is the why of a gap what=enforce the forwarder writes for each route change of a models[]
// endpoint it put in force (ADR 0127): the endpoint's requests go to model_route.route from the next one on.
const GapModelRouteChanged = "model-route-changed"

// ModelRouteRule is the rule a request refused for its route (ReasonModelRouteChanged) carries: the models[] entry's
// routes, models[<host:port>].routes.
func ModelRouteRule(model string) string { return "models[" + model + "].routes" }

// modelRouteRule reports whether rule is one MinorModelRoutes added, models[<authority>].routes.
func modelRouteRule(rule string) bool {
	return strings.HasPrefix(rule, "models[") && strings.HasSuffix(rule, "].routes")
}

// RouteDirect is the route of a models[] endpoint's own upstream (pkg/spec/agent.DirectRoute): every run starts on it,
// and a person's revert returns to it.
const RouteDirect = "direct"

// RouteTaken names the route one model request went by (MinorModelRoutes): the route's name, direct for the models[]
// endpoint itself, and the backend's authority, host:port. It is on every ssl_request line of an endpoint that
// declares routes, and on the net line of a credential injected into or refused for such a request; absent from
// every line of an endpoint without routes.
type RouteTaken struct {
	Name      string `json:"name"`
	Authority string `json:"authority"`
}

// ModelRouteChange is one route change of a models[] endpoint, as the run's route overlay recorded it: the endpoint
// (its declared authority), the route now in force and its backend's authority, who made it ("uid:<uid> pid:<pid>
// <via>"), its serial in the overlay (from 1) and when.
type ModelRouteChange struct {
	Model     string    `json:"model"`
	Route     string    `json:"route"`
	Authority string    `json:"authority"`
	By        string    `json:"by"`
	Serial    uint64    `json:"serial"`
	At        time.Time `json:"at"`
}

// routeNameRE is a route's name rule (pkg/spec/agent's models[].routes names; direct is the endpoint's own).
var routeNameRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// authorityOK reports whether s is host:port with a non-empty host and a port from 1 to 65535.
func authorityOK(s string) bool {
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// validateModelRoute is ValidateAt's check of the model routing fields (MinorModelRoutes, ADR 0127) on e and its
// payload's members fields:
//   - below the revision, a route, a model_route, a why or a reason model-route-changed and a models[<m>].routes rule
//     are refused [below-minor];
//   - route is on an ssl_request or a net line only, with a route name and a host:port authority [model-route];
//   - a reason model-route-changed is on a refused net line that names its route [model-route];
//   - model_route is on a gap what=enforce why model-route-changed and only there, every such line has one, with a
//     model and an authority of host:port, a route name and a serial of 1 or more; 0 only on a revert to direct the
//     forwarder found with no change numbering it (the overlay removed, or replaced by one that starts again)
//     [model-route];
//   - a member a case-insensitive reader would take for either but spelt otherwise is refused [field-case].
func (e *Event) validateModelRoute(minor int, fields []field) error {
	if minor < MinorModelRoutes {
		if e.Reason == ReasonModelRouteChanged {
			return fieldErr("below-minor", "reason", "%q is added at record_minor %d, the ledger is at %d", e.Reason,
				MinorModelRoutes, minor)
		}
		if modelRouteRule(e.Rule) {
			return fieldErr("below-minor", "rule", "%q is added at record_minor %d, the ledger is at %d", e.Rule,
				MinorModelRoutes, minor)
		}
	}
	var route, change []byte
	var why, what string
	for _, fl := range fields {
		switch {
		case fl.key == routeKey:
			route = fl.val
		case fl.key == modelRouteKey:
			change = fl.val
		case fl.key == "why":
			_ = jsonv2.Unmarshal(fl.val, &why) // not a string: "" matches no rule here
		case fl.key == "what":
			_ = jsonv2.Unmarshal(fl.val, &what) // as why
		case foldEqual(fl.key, routeKey) && (e.Kind == KindSSLRequest || e.Kind == KindNet):
			return fieldErr("field-case", string(e.Kind)+"."+routeKey, "the key %q is not spelt %q", fl.key, routeKey)
		case foldEqual(fl.key, modelRouteKey):
			return fieldErr("field-case", string(e.Kind)+"."+modelRouteKey, "the key %q is not spelt %q", fl.key, modelRouteKey)
		}
	}
	if route != nil && (e.Kind == KindSSLRequest || e.Kind == KindNet) {
		f := string(e.Kind) + "." + routeKey
		if err := belowMinor(f, true, minor, MinorModelRoutes); err != nil {
			return err
		}
		var r RouteTaken
		if err := decodeField(f, route, &r); err != nil {
			return err
		}
		switch {
		case !routeNameRE.MatchString(r.Name):
			return fieldErr("model-route", f+".name", "%q is not a route name (^[a-z0-9-]{1,40}$)", r.Name)
		case !authorityOK(r.Authority):
			return fieldErr("model-route", f+".authority", "%q is not host:port", r.Authority)
		}
	}
	if e.Reason == ReasonModelRouteChanged && (e.Kind != KindNet || e.Verdict != VerdictRefused || route == nil) {
		return fieldErr("model-route", "reason", "%q is on a refused net line that names its route", e.Reason)
	}
	if e.Kind != KindGap {
		if change != nil {
			return fieldErr("model-route", string(e.Kind)+"."+modelRouteKey, "on a %s line, not a gap why %q", e.Kind, GapModelRouteChanged)
		}
		return nil
	}
	const f = "gap." + modelRouteKey
	if why == GapModelRouteChanged && minor < MinorModelRoutes {
		return fieldErr("below-minor", "gap.why", "why %q is added at record_minor %d, the ledger is at %d", why,
			MinorModelRoutes, minor)
	}
	if change == nil {
		if why == GapModelRouteChanged {
			return fieldErr("model-route", f, "a why %q line without %s", why, modelRouteKey)
		}
		return nil
	}
	if err := belowMinor(f, true, minor, MinorModelRoutes); err != nil {
		return err
	}
	var c ModelRouteChange
	if err := decodeField(f, change, &c); err != nil {
		return err
	}
	switch {
	case why != GapModelRouteChanged:
		return fieldErr("model-route", f, "on a gap why %q, not %q", why, GapModelRouteChanged)
	case what != GapEnforce:
		return fieldErr("model-route", f, "on a gap what %q, not %q", what, GapEnforce)
	case !authorityOK(c.Model):
		return fieldErr("model-route", f+".model", "%q is not a models[] endpoint, host:port", c.Model)
	case !routeNameRE.MatchString(c.Route):
		return fieldErr("model-route", f+".route", "%q is not a route name (^[a-z0-9-]{1,40}$)", c.Route)
	case !authorityOK(c.Authority):
		return fieldErr("model-route", f+".authority", "%q is not host:port", c.Authority)
	case c.Serial == 0 && c.Route != RouteDirect:
		return fieldErr("model-route", f+".serial", "0: an overlay numbers its changes from 1; only a revert to direct "+
			"no change numbered has none")
	}
	return nil
}
