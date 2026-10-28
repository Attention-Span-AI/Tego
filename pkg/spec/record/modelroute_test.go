// SPDX-License-Identifier: Apache-2.0

package record

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var modelRouteDir = filepath.Join(fixturesDir, "modelroute")

// TestRecordMinorCoversModelRoutes: model routes are revision 27, the next free one after the live modes' 26
// (TestRecordMinorsAreContiguous), and this build writes it.
func TestRecordMinorCoversModelRoutes(t *testing.T) {
	if MinorModelRoutes != MinorLiveModes+1 || Minor < MinorModelRoutes {
		t.Fatalf("Minor %d, MinorModelRoutes %d, MinorLiveModes %d", Minor, MinorModelRoutes, MinorLiveModes)
	}
	if RouteDirect != "direct" {
		t.Fatal(RouteDirect)
	}
}

// TestModelRouteFieldFixtures: every valid document of fixtures/modelroute passes ValidateAt at its revision; every
// invalid one is refused with the code its file name starts with, and below-minor, field-case and model-route each have
// one.
func TestModelRouteFieldFixtures(t *testing.T) {
	valid, _ := filepath.Glob(filepath.Join(modelRouteDir, "valid", "*.json"))
	invalid, _ := filepath.Glob(filepath.Join(modelRouteDir, "invalid", "*.json"))
	if len(valid) < 6 || len(invalid) < 10 {
		t.Fatalf("%d valid and %d invalid fixtures; want at least 6 and 10", len(valid), len(invalid))
	}
	for _, f := range valid {
		e, minor := credEvent(t, f)
		if err := e.ValidateAt(minor); err != nil {
			t.Errorf("%s: refused: %v", filepath.Base(f), err)
		}
		if _, err := e.MarshalLineAt(minor); err != nil {
			t.Errorf("%s: MarshalLineAt refused: %v", filepath.Base(f), err)
		}
	}
	seen := map[string]bool{}
	for _, f := range invalid {
		code, _, _ := strings.Cut(filepath.Base(f), ".")
		seen[code] = true
		e, minor := credEvent(t, f)
		err := e.ValidateAt(minor)
		if got := FieldCode(err); got != code {
			t.Errorf("%s: %v [%s], want [%s]", filepath.Base(f), err, got, code)
		}
		if err != nil && !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: %v is not ErrInvalidEvent", filepath.Base(f), err)
		}
	}
	for _, c := range []string{"below-minor", "field-case", "model-route"} {
		if !seen[c] {
			t.Errorf("no invalid fixture of fixtures/modelroute shows [%s]", c)
		}
	}
}

// TestModelRouteBelowAndAtTheRevision: the route on a request line, on a credential's net line and a route change
// pass at 27 and are refused [below-minor] at 26; a request line without a route passes at 26; the forwarder's own
// payload types marshal to the fields the validator reads.
func TestModelRouteBelowAndAtTheRevision(t *testing.T) {
	ts := time.Date(2026, 10, 27, 18, 3, 1, 0, time.UTC)
	ev := func(kind Kind, p any) *Event {
		e := &Event{V: Version, Kind: kind, Source: SourceForwarder, Run: "r-00000000-000000000000a-aaaaaa", Agent: "a", TS: ts}
		if kind == KindNet {
			e.Rule, e.Verdict, e.Authority, e.Attr = "credential[corp]", VerdictAllow, AuthorityRule, Unattributed()
		}
		if err := e.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		return e
	}
	route := &RouteTaken{Name: "corp", Authority: "llm-proxy.corp.example:8443"}
	cases := map[string]*Event{
		"request": ev(KindSSLRequest, SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages",
			Host: "api.anthropic.com", Size: 3, Route: route}),
		"credential": ev(KindNet, NetPayload{Op: "http_request", Proto: "http", Dst: route.Authority,
			Credential: &CredentialUse{Name: "corp", Version: 1}, Route: route}),
		"change": ev(KindGap, GapPayload{What: GapEnforce, Why: GapModelRouteChanged, ModelRoute: &ModelRouteChange{
			Model: "api.anthropic.com:443", Route: "corp", Authority: route.Authority, By: "uid:1 pid:2 cli", Serial: 3, At: ts}}),
	}
	for name, e := range cases {
		if err := e.ValidateAt(MinorModelRoutes); err != nil {
			t.Errorf("%s at 27: %v", name, err)
		}
		if got := FieldCode(e.ValidateAt(MinorLiveModes)); got != "below-minor" {
			t.Errorf("%s at 26: [%s], want [below-minor]", name, got)
		}
	}
	plain := ev(KindSSLRequest, SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/", Host: "h", Size: 1})
	if err := plain.ValidateAt(MinorLiveModes); err != nil {
		t.Errorf("a request without a route at 26: %v", err)
	}
	onExec := ev(KindGap, GapPayload{What: GapEnforce, Why: GapPlaneNoRows, ModelRoute: cases["change"].mustRoute(t)})
	if got := FieldCode(onExec.ValidateAt(Minor)); got != "model-route" {
		t.Errorf("a model_route on another why: [%s]", got)
	}
}

// mustRoute is e's model_route, decoded.
func (e *Event) mustRoute(t *testing.T) *ModelRouteChange {
	t.Helper()
	var p GapPayload
	if err := e.DecodePayload(&p); err != nil || p.ModelRoute == nil {
		t.Fatalf("no model_route: %v", err)
	}
	return p.ModelRoute
}
