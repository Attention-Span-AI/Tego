// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/modelroutes"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// C208 (ADR 0125, ADR 0127 Amendment 2026-11-21): a Locked run keeps every endpoint on its own backend whatever the route
// overlay holds. `tego route` and the dashboard refuse the change; this is the consumer's half, for an overlay written
// some other way.

func TestLockedRunKeepsTheEndpointOnItsOwnBackend(t *testing.T) {
	rh := newLockedRouteHarness(t, Options{})
	own := rh.listener.authority()
	rh.set(t, "alt")
	for range 2 {
		if code, _ := rh.send(t, nil); code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
	}
	if rh.direct.Load() != 2 || rh.altHits.Load() != 0 || rh.plainHits.Load() != 0 {
		t.Fatalf("direct %d, alt %d, plain %d: a request of a Locked run went by a route", rh.direct.Load(), rh.altHits.Load(), rh.plainHits.Load())
	}
	for _, ev := range rh.sink.waitFor(t, record.KindSSLRequest, 2)[:2] {
		if r := routeOf(t, ev); r == nil || r.Name != "direct" || r.Authority != own {
			t.Fatalf("a request line names the route %+v", r)
		}
	}
	// The change is one line, which says what is in force (direct), who asked and why it did not take effect.
	ch := routeChanges(t, rh.sink)
	if len(ch) != 1 || ch[0].Route != "direct" || ch[0].Authority != own || ch[0].Model != own || ch[0].Serial != 1 ||
		ch[0].By != "uid:1000 pid:1 cli"+HeldByLocked {
		t.Fatalf("change lines %+v", ch)
	}
	// Every line is one this record revision reads, and an older reader reads it as the ordinary revert it looks like.
	for _, ev := range rh.sink.all() {
		if b, err := ev.MarshalLineAt(record.Minor); err != nil {
			t.Errorf("%s line not valid at %d: %v (%s)", ev.Kind, record.Minor, err, b)
		}
	}
}

func TestLockedRunHoldsEveryRouteTheOverlayNames(t *testing.T) {
	rh := newLockedRouteHarness(t, Options{})
	rh.set(t, "alt")
	rh.set(t, "plain")
	rh.set(t, "evil") // not declared: ignored with a log line, as on an Adjustable run
	rh.set(t, "alt")
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 1 {
		t.Fatalf("status %d, direct %d", code, rh.direct.Load())
	}
	if ch := routeChanges(t, rh.sink); len(ch) != 3 {
		t.Fatalf("change lines %+v, want one for each declared route asked for", ch)
	}
}

// TestLockedRunWithAnUnreadableOverlayStaysDirect: an overlay the forwarder cannot read never opens a route on a Locked run.
func TestLockedRunWithAnUnreadableOverlayStaysDirect(t *testing.T) {
	rh := newLockedRouteHarness(t, Options{})
	rh.set(t, "alt")
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 1 || rh.altHits.Load() != 0 {
		t.Fatalf("status %d, direct %d, alt %d", code, rh.direct.Load(), rh.altHits.Load())
	}
	if err := os.Chmod(filepath.Join(rh.dir, modelroutes.FileName), 0o666); err != nil { // one another user could write
		t.Fatal(err)
	}
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 2 || rh.altHits.Load() != 0 {
		t.Fatalf("after the overlay became untrusted: status %d, direct %d, alt %d", code, rh.direct.Load(), rh.altHits.Load())
	}
}

// TestLockedRunStartsWithTheRoutesThatAreThere: a route in the overlay when the run starts is held back and has its
// line (the first read replays no history, so the line comes from the overlay's own entry).
func TestLockedRunStartsWithTheRoutesThatAreThere(t *testing.T) {
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443,
		Routes: []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 8443}}}
	for _, adjustable := range []bool{false, true} {
		m, err := NewManager([]agent.ModelEndpoint{model}, Options{Clock: newClock(), Rand: &countingRand{}, Adjustable: adjustable})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if _, err := modelroutes.Update(context.Background(), dir, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
			return o.Set("api.anthropic.com:443", "corp", "uid:1 pid:2 other", time.Now())
		}); err != nil {
			t.Fatal(err)
		}
		sink := &fakeSink{}
		if err := m.Start(context.Background(), source.RunRef{ID: testRun.ID, Agent: "a", Dir: dir}, sink); err != nil {
			t.Fatal(err)
		}
		ch := waitChanges(t, sink, 1)
		if len(ch) != 1 || ch[0].Serial != 1 {
			t.Fatalf("adjustable %v: change lines %+v", adjustable, ch)
		}
		if adjustable && ch[0].Route != "corp" {
			t.Fatalf("an Adjustable run did not put the route in force: %+v", ch[0])
		}
		if !adjustable && (ch[0].Route != "direct" || !strings.HasSuffix(ch[0].By, HeldByLocked)) {
			t.Fatalf("a Locked run's line %+v", ch[0])
		}
		if err := m.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRouterWithoutAModeIsLocked(t *testing.T) {
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443,
		Routes: []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 8443}}}
	if rt := newRouter([]agent.ModelEndpoint{model}, nil); rt == nil || rt.adjustable {
		t.Fatal("a router made without a mode is not Locked")
	}
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Clock: newClock(), Rand: &countingRand{}})
	if err != nil {
		t.Fatal(err)
	}
	if m.routes.adjustable {
		t.Fatal("a Manager built without a mode is Adjustable")
	}
}
