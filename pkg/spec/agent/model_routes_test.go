// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"strings"
	"testing"
)

// routeContract is a valid contract whose anthropic endpoint declares two routes, %s replaced by extra top-level keys.
const routeContract = `version: 0
name: t
command: ["python"]
capture: forwarder
models:
  - provider: anthropic
    host: api.anthropic.com
    port: 443
    routes:
      - {name: corp, host: llm-proxy.corp.example, port: 8443}
      - {name: local, host: 127.0.0.1, port: 11434, tls: false}
%s`

// TestModelRoutesAccepted: declared routes load, with their authorities and TLS, and a credential may name a route's
// backend.
func TestModelRoutesAccepted(t *testing.T) {
	extra := "credentials:\n  - {name: corp, env: ANTHROPIC_API_KEY, allow: [api.anthropic.com, \"llm-proxy.corp.example:8443\"]}\n"
	c, ds := loadDiags(t, strings.Replace(routeContract, "%s", extra, 1))
	if c == nil {
		t.Fatalf("refused: %s", render(ds))
	}
	m := c.Models[0]
	if got := m.RouteAuthorities(); !slices.Equal(got, []string{"llm-proxy.corp.example:8443", "127.0.0.1:11434"}) {
		t.Errorf("RouteAuthorities = %q", got)
	}
	corp, ok := m.Route("corp")
	if !ok || !corp.UsesTLS() {
		t.Errorf("corp = %+v %v", corp, ok)
	}
	local, ok := m.Route("local")
	if !ok || local.UsesTLS() {
		t.Errorf("local = %+v %v", local, ok)
	}
	if _, ok := m.Route(DirectRoute); ok {
		t.Error("direct is a declared route")
	}
}

// TestModelRoutesRefused: every refusal of R32, each by its code and words.
func TestModelRoutesRefused(t *testing.T) {
	sub := func(old, new string) string {
		return strings.Replace(strings.Replace(routeContract, old, new, 1), "%s", "", 1)
	}
	for _, tc := range []struct {
		name, yaml, code, words string
	}{
		{"no capture", sub("capture: forwarder\n", ""), CodeContradiction, "need capture: forwarder"},
		{"named direct", sub("name: corp", "name: direct"), CodeSchema, "own endpoint"},
		{"bad name", sub("name: corp", "name: Corp_Proxy"), CodeSchema, "must match"},
		{"dup name", sub("name: local", "name: corp"), CodeSchema, "already used"},
		{"the endpoint itself", sub("host: llm-proxy.corp.example, port: 8443", "host: api.anthropic.com, port: 443"), CodeContradiction, "the direct route"},
		{"same backend twice", sub("host: 127.0.0.1, port: 11434, tls: false", "host: llm-proxy.corp.example, port: 8443"), CodeContradiction, "as route 1 does"},
		{"plaintext off the machine", sub("host: 127.0.0.1, port: 11434, tls: false", "host: 10.0.0.5, port: 11434, tls: false"), CodeContradiction, "in the clear"},
		{"no port", sub("port: 8443}", "}"), CodeSchema, "port"},
		{"bad tls", sub("tls: false", "tls: maybe"), CodeSchema, "tls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds := loadDiags(t, tc.yaml)
			for _, d := range ds {
				if d.Severity == SeverityError && d.Code == tc.code && strings.Contains(d.Message, tc.words) {
					return
				}
			}
			t.Fatalf("want %s %q, got %s", tc.code, tc.words, render(ds))
		})
	}
	t.Run("endpoint twice", func(t *testing.T) {
		y := strings.Replace(routeContract, "%s", "", 1)
		y = strings.Replace(y, "models:\n", "models:\n  - {provider: anthropic, host: api.anthropic.com, port: 443}\n", 1)
		_, ds := loadDiags(t, y)
		for _, d := range ds {
			if d.Severity == SeverityError && strings.Contains(d.Message, "needs one entry") {
				return
			}
		}
		t.Fatalf("no refusal: %s", render(ds))
	})
	t.Run("credential to an undeclared backend", func(t *testing.T) {
		y := strings.Replace(routeContract, "%s", "credentials:\n  - {name: c, env: ANTHROPIC_API_KEY, allow: [\"llm-proxy.corp.example:9999\"]}\n", 1)
		_, ds := loadDiags(t, y)
		for _, d := range ds {
			if d.Severity == SeverityError && strings.Contains(d.Message, "not a declared models[] endpoint or route") {
				return
			}
		}
		t.Fatalf("no refusal: %s", render(ds))
	})
}

// TestModelRoutesLocalhostPlaintext: tls: false is allowed on the name localhost and every loopback address, and refused
// on a name under .localhost, which a resolver that does not apply RFC 6761 sends to DNS.
func TestModelRoutesLocalhostPlaintext(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "127.0.0.2", "LOCALHOST."} {
		y := strings.Replace(strings.Replace(routeContract, "host: 127.0.0.1, port: 11434", "host: \""+host+"\", port: 11434", 1), "%s", "", 1)
		if c, ds := loadDiags(t, y); c == nil {
			t.Errorf("%s refused: %s", host, render(ds))
		}
	}
	for _, host := range []string{"models.localhost", "localhost.example"} {
		y := strings.Replace(strings.Replace(routeContract, "host: 127.0.0.1, port: 11434", "host: "+host+", port: 11434", 1), "%s", "", 1)
		if c, ds := loadDiags(t, y); c != nil || !strings.Contains(render(ds), "tls: false") {
			t.Errorf("%s accepted: %s", host, render(ds))
		}
	}
}

// TestModelRoutesRefusedUnderObserve: routes do not compile under --observe, where nothing keeps the agent from writing
// its own route overlay, nor where the machine's capture ceiling is below the forwarder (ADR 0127 §1, R32).
func TestModelRoutesRefusedUnderObserve(t *testing.T) {
	f := newFixture(t)
	c := f.load(strings.Replace(routeContract, "%s", "", 1))
	_, ds, err := Compile(c, f.machine, f.opts(WithObserve())...)
	if err == nil && !hasCode(ds, CodeContradiction) {
		t.Fatalf("observe compiled: %s", render(ds))
	}
	if !strings.Contains(render(ds), "models routes: cannot run under --observe") {
		t.Errorf("no observe refusal: %s", render(ds))
	}
	if _, ds, err := Compile(c, f.machine, f.opts()...); err != nil || hasCode(ds, CodeContradiction) {
		t.Fatalf("an enforcing run refused: %v %s", err, render(ds))
	}
}

// TestModelRoutesRefusedUnderALoweredCapture: a machine whose capture ceiling is below the forwarder refuses a routed
// contract, since no forwarder would carry its requests.
func TestModelRoutesRefusedUnderALoweredCapture(t *testing.T) {
	for _, ceiling := range []string{"off"} {
		f := newFixture(t)
		c := f.load(strings.Replace(routeContract, "%s", "", 1))
		m := *f.machine
		m.Capture = capCeil(ceiling)
		_, ds, err := Compile(c, &m, f.opts()...)
		if err == nil && !hasCode(ds, CodeContradiction) {
			t.Fatalf("capture %s compiled: %s", ceiling, render(ds))
		}
		if !strings.Contains(render(ds), "models routes: need the forwarder, and this machine runs capture") {
			t.Errorf("capture %s: no ceiling refusal: %s", ceiling, render(ds))
		}
	}
}

// TestGuardedModelsHoldRouteBackends: an enforcing forwarder run guards each route's backend as it guards the models[]
// endpoint, so the agent cannot reach a declared backend around the forwarder (uncaptured, unbudgeted, unrecorded).
func TestGuardedModelsHoldRouteBackends(t *testing.T) {
	f := newFixture(t)
	c := f.load(strings.Replace(routeContract, "%s", "", 1))
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	var got []string
	for _, m := range rt.GuardedModels() {
		got = append(got, ModelRule(m))
	}
	want := []string{"models[api.anthropic.com:443]", "models[llm-proxy.corp.example:8443]", "models[127.0.0.1:11434]"}
	if !slices.Equal(got, want) {
		t.Fatalf("GuardedModels = %q, want %q", got, want)
	}
}

// TestContractHashUnchangedWithoutRoutes: a contract that declares no route has the canonical bytes it had before
// routes existed, and one that declares a route hashes differently.
func TestContractHashUnchangedWithoutRoutes(t *testing.T) {
	const plain = "version: 0\nname: t\ncommand: [\"python\"]\ncapture: forwarder\nmodels:\n  - {provider: anthropic, host: api.anthropic.com, port: 443}\n"
	c, ds := loadDiags(t, plain)
	if c == nil {
		t.Fatal(render(ds))
	}
	b, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "routes") {
		t.Fatalf("canonical bytes name routes:\n%s", b)
	}
	const want = "version: 0\nname: t\ncommand:\n  - python\nmodels:\n  - provider: anthropic\n    host: api.anthropic.com\n    port: 443\ncapture: forwarder\n"
	if string(b) != want {
		t.Fatalf("canonical bytes changed:\n%s", b)
	}
	r, ds := loadDiags(t, strings.Replace(routeContract, "%s", "", 1))
	if r == nil {
		t.Fatal(render(ds))
	}
	h0, _ := c.Hash()
	h1, _ := r.Hash()
	if h0 == h1 {
		t.Fatal("a contract with routes hashes as one without")
	}
}
