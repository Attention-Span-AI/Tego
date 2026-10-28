// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/modelroutes"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

const routeCLIContract = `version: 0
name: tester
command: ["true"]
capture: forwarder
models:
  - provider: anthropic
    host: api.anthropic.com
    port: 443
    routes:
      - {name: corp, host: llm-proxy.corp.example, port: 8443}
      - {name: local, host: 127.0.0.1, port: 11434, tls: false}
  - {provider: openai, host: api.openai.com, port: 443}
`

// routedRun is a live run whose contract copy declares routes, with the governed check answering "outside every run".
func routedRun(t *testing.T) (dir, id string) {
	t.Helper()
	dir, id, _ = liveRun(t)
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(routeCLIContract), 0o600); err != nil {
		t.Fatal(err)
	}
	old := selfInRun
	selfInRun = func() (bool, error) { return false, nil }
	t.Cleanup(func() { selfInRun = old })
	return dir, id
}

// TestRouteListSetClear: list shows each endpoint on direct with its declared routes; set --yes moves one to a declared
// route, written to the run's overlay by the cli; set again changes nothing; clear sends it back; --json says the same.
func TestRouteListSetClear(t *testing.T) {
	dir, id := routedRun(t)
	code, out, errs := run(t, "route", "list", id)
	if code != identity.ExitOK || !strings.Contains(out, "api.anthropic.com:443 (anthropic): route direct, sends to api.anthropic.com:443") ||
		!strings.Contains(out, "corp") || !strings.Contains(out, "plaintext") || !strings.Contains(out, "api.openai.com:443 (openai)") ||
		!strings.Contains(out, "no routes declared") {
		t.Fatalf("list: exit %d stdout %q stderr %q", code, out, errs)
	}
	code, out, errs = run(t, "route", "set", "--yes", id, "anthropic", "corp")
	if code != identity.ExitOK || !strings.Contains(out, "now sends to corp (llm-proxy.corp.example:8443); it was on direct") {
		t.Fatalf("set: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := modelroutes.Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := o.Lookup("api.anthropic.com:443"); !ok || e.Route != "corp" || !strings.HasSuffix(e.By, " cli") {
		t.Fatalf("overlay %+v", o)
	}
	if code, out, _ = run(t, "route", "set", "--yes", id, "api.anthropic.com", "corp"); code != identity.ExitOK || !strings.Contains(out, "already on route corp") {
		t.Fatalf("set again: exit %d stdout %q", code, out)
	}
	code, out, _ = run(t, "route", "list", "--json", id)
	var doc struct {
		V      int `json:"v"`
		Models []struct {
			Endpoint string `json:"endpoint"`
			Route    string `json:"route"`
		} `json:"models"`
	}
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &doc) != nil || doc.V != 1 || len(doc.Models) != 2 || doc.Models[0].Route != "corp" {
		t.Fatalf("list --json: exit %d %q", code, out)
	}
	if !strings.Contains(out, `"route": "corp"`) || !strings.Contains(out, `"sends_to": "llm-proxy.corp.example:8443"`) {
		t.Fatalf("list --json: %s", out)
	}
	if code, out, errs = run(t, "route", "clear", id, "api.anthropic.com:443"); code != identity.ExitOK || !strings.Contains(out, "now sends to direct (api.anthropic.com:443); it was on corp") {
		t.Fatalf("clear: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, _ = modelroutes.Read(dir, id)
	if _, ok := o.Lookup("api.anthropic.com:443"); ok || len(o.Changes) != 2 || o.Changes[1].Op != modelroutes.OpClear {
		t.Fatalf("overlay after clear %+v", o)
	}
}

// TestRouteSetRefusals: an undeclared route, an unknown endpoint, a widening not confirmed, and any change from
// inside a run (set or clear) change nothing.
func TestRouteSetRefusals(t *testing.T) {
	dir, id := routedRun(t)
	if code, _, errs := run(t, "route", "set", "--yes", id, "anthropic", "evil"); code != identity.ExitUsage || !strings.Contains(errs, "declares no route evil") ||
		!strings.Contains(errs, "declared: direct, corp, local") {
		t.Fatalf("undeclared route: exit %d stderr %q", code, errs)
	}
	if code, _, errs := run(t, "route", "set", "--yes", id, "api.example.com", "corp"); code != identity.ExitUsage || !strings.Contains(errs, "no models[] endpoint") {
		t.Fatalf("unknown endpoint: exit %d stderr %q", code, errs)
	}
	if code, _, errs := run(t, "route", "set", "--yes", id, "openai", "corp"); code != identity.ExitUsage || !strings.Contains(errs, "declares no route corp") {
		t.Fatalf("a route of another endpoint: exit %d stderr %q", code, errs)
	}
	old := routeStdin
	routeStdin = strings.NewReader("n\n")
	t.Cleanup(func() { routeStdin = old })
	if code, out, _ := run(t, "route", "set", id, "anthropic", "local"); code != identity.ExitFinding || !strings.Contains(out, "Go ahead? [y/N]") ||
		!strings.Contains(out, "Nothing changed.") {
		t.Fatalf("unconfirmed widening: exit %d stdout %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, modelroutes.FileName)); !os.IsNotExist(err) {
		t.Fatalf("an overlay was written: %v", err)
	}
	selfInRun = func() (bool, error) { return true, nil }
	for _, args := range [][]string{{"route", "set", "--yes", id, "anthropic", "corp"}, {"route", "clear", id, "anthropic"}} {
		if code, _, errs := run(t, args...); code != identity.ExitFinding || !strings.Contains(errs, "a governed agent cannot change its own governance") {
			t.Fatalf("%v from inside a run: exit %d stderr %q", args, code, errs)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, modelroutes.FileName)); !os.IsNotExist(err) {
		t.Fatalf("an overlay was written: %v", err)
	}
}

// TestRouteSetRecheckedUnderTheLock: `tego route set` without --yes skips the question when the endpoint is already on
// the route; a clear made before the writers' lock turns that into a widening nobody confirmed, which is refused and
// leaves the clear in force.
func TestRouteSetRecheckedUnderTheLock(t *testing.T) {
	dir, id := routedRun(t)
	if code, _, errs := run(t, "route", "set", "--yes", id, "anthropic", "corp"); code != identity.ExitOK {
		t.Fatalf("set: exit %d stderr %q", code, errs)
	}
	routeBeforeLock = func() {
		if _, err := modelroutes.Update(context.Background(), dir, id, func(o *modelroutes.Overlay) (bool, error) {
			return o.Clear("api.anthropic.com:443", "uid:1 pid:3 cli", time.Now())
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { routeBeforeLock = nil })
	code, out, errs := run(t, "route", "set", id, "anthropic", "corp")
	if code != identity.ExitFinding || strings.Contains(out, "Go ahead?") || !strings.Contains(errs, "moved to direct while this ran") {
		t.Fatalf("stale set: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := modelroutes.Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Lookup("api.anthropic.com:443"); ok {
		t.Fatalf("overlay %+v", o)
	}
}

// TestRouteQuestionPromisesWhatTheBuildDoes: the y/N says what a route carries, a key the agent holds itself included,
// and no rule of a layer the build has not got: with no key layer that key goes wherever the route goes, so words on an
// allow list would be false at the moment a person consents. A layer's sentence comes after the core's.
func TestRouteQuestionPromisesWhatTheBuildDoes(t *testing.T) {
	old := routeKeyNote
	t.Cleanup(func() { routeKeyNote = old })

	routeKeyNote = ""
	q := routeQuestion("api.anthropic.com:443", "run-1", "corp", "llm-proxy.corp.example:8443")
	if !strings.Contains(q, "a key the agent holds itself goes there too") {
		t.Errorf("the question does not say a key travels: %q", q)
	}
	for _, promise := range []string{"allow", "credential"} {
		if strings.Contains(q, promise) {
			t.Errorf("a build with no key layer promises %q: %q", promise, q)
		}
	}

	routeKeyNote = "A layer's sentence."
	if q := routeQuestion("a:443", "run-1", "corp", "b:8443"); !strings.HasSuffix(q, "goes there too. A layer's sentence.") {
		t.Errorf("the layer's sentence: %q", q)
	}
}
