// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/modelroutes"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
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

// routedRun is a live Adjustable run (ADR 0125) whose contract copy declares routes, with the governed check answering
// "outside every run".
func routedRun(t *testing.T) (dir, id string) {
	t.Helper()
	dir, id = lockedRoutedRun(t)
	adjustableStart(t, dir)
	return dir, id
}

// adjustableStart makes the stand-in run's run_start in dir an Adjustable run's at record minor 26, with an empty fence.
func adjustableStart(t *testing.T, dir string) {
	t.Helper()
	rewriteStart(t, dir, `"tier":"landlock"`, fmt.Sprintf(`"tier":"cgroup","record_minor":%d,"live_mode":"adjustable","live_fence":{"sha256":"%s","entries":[]}`,
		record.MinorLiveModes, strings.Repeat("0", 64)))
}

// lockedRoutedRun is routedRun with the run Locked, the default: its run_start names no live mode.
func lockedRoutedRun(t *testing.T) (dir, id string) {
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

// lockedWordsCLI is what a Locked run's refusal of a loosening says on the terminal, after the run's id: a lift's words.
const lockedWordsCLI = " is Locked: it keeps to its contract while it runs, so nothing loosens until its next run; " +
	"to loosen live, choose Adjustable for the next run (live.mode: adjustable, ADR 0125)"

// TestRouteSetRefusedOnALockedRun: on a Locked run (ADR 0125, ADR 0127 §6) `tego route set` to any route but direct is
// refused [locked], exit 1, in the words `tego lift` says for a Locked run, with --yes too; nothing is written, neither
// the overlay nor the run's ledger (a writer's refusal is not a ledger line, as a refused lift is not). A clear, back
// to the contract's direct, is taken. A first line that does not decode is refused too, as not readable
// [start-unreadable].
func TestRouteSetRefusedOnALockedRun(t *testing.T) {
	dir, id := lockedRoutedRun(t)
	events := filepath.Join(dir, ledger.EventsFile)
	before, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"corp", "local"} {
		code, out, errs := run(t, "route", "set", "--yes", id, "anthropic", route)
		if code != identity.ExitFinding || !strings.Contains(errs, "tego route set: "+id+lockedWordsCLI) || !strings.Contains(errs, "[locked]") ||
			strings.Contains(out, "now sends") {
			t.Fatalf("set %s on a Locked run: exit %d stdout %q stderr %q", route, code, out, errs)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, modelroutes.FileName)); !os.IsNotExist(err) {
		t.Fatalf("an overlay was written: %v", err)
	}
	if b, err := os.ReadFile(events); err != nil || string(b) != string(before) {
		t.Fatalf("the refusal changed the run's ledger: %v", err)
	}
	if code, out, errs := run(t, "route", "clear", id, "anthropic"); code != identity.ExitOK || strings.Contains(errs, "Locked") {
		t.Fatalf("clear on a Locked run: exit %d stdout %q stderr %q", code, out, errs)
	}
	if err := os.WriteFile(events, []byte("{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, "route", "set", "--yes", id, "anthropic", "corp"); code != identity.ExitFinding || !strings.Contains(errs, "[start-unreadable]") {
		t.Fatalf("an unreadable run_start: exit %d stderr %q", code, errs)
	}
}

// TestALiveChangeToARunStillStartingSaysSo: a run's launcher holds its lock a few seconds before its run_start line is
// in events.jsonl (acceptance 2B, 2026-11-11: a slow BPF load on 2 vCPUs, 3 s). In that window `tego mcp allow` said
// the run "is Locked", and seconds later it worked: the mode was read before it was written, and a mode not known read
// as Locked. Each live writer that decides on the mode or the launcher's facts now refuses there, exit 1 [starting],
// in words that say the run is still starting and to try again, never "Locked" or "older tego"; nothing is written.
// A change that needs no fact (a plain block, a clear back to the contract) is taken as before.
func TestALiveChangeToARunStillStartingSaysSo(t *testing.T) {
	noTerminal(t, false, "")
	starting := func(t *testing.T, dir string, args ...string) {
		t.Helper()
		events := filepath.Join(dir, ledger.EventsFile)
		if err := os.WriteFile(events, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errs := run(t, args...)
		if code != identity.ExitFinding || !strings.Contains(errs, "[starting]") || !strings.Contains(errs, " is still starting") ||
			!strings.Contains(errs, "try again in a few seconds") || strings.Contains(errs, "Locked") || strings.Contains(errs, "older tego") {
			t.Errorf("%v while the run starts: exit %d stdout %q stderr %q", args, code, out, errs)
		}
		for _, f := range []string{mcptools.FileName, modelroutes.FileName, liveblock.FileName} {
			if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
				t.Errorf("%v wrote %s: %v", args, f, err)
			}
		}
		if b, _ := os.ReadFile(events); len(b) != 0 {
			t.Errorf("%v wrote the run's ledger: %q", args, b)
		}
	}
	t.Run("mcp", func(t *testing.T) {
		dir, id := mcpRun(t, true)
		starting(t, dir, "mcp", "allow", "--yes", id, "files", "delete_file")
	})
	t.Run("route, lift, grant, restore, block", func(t *testing.T) {
		dir, id := routedRun(t)
		for _, args := range [][]string{
			{"route", "set", "--yes", id, "anthropic", "corp"},
			{"lift", id, "net", "127.0.0.1:9", "--yes"},
			{"grant", id, "net", "127.0.0.1:9", "--for", "5m", "--yes"},
			{"restore", id, "net", "127.0.0.1:9"},
			{"block", id, "exec", "/usr/bin/curl", "--for", "5m"},
			{"block", id, "read", "/etc/hostname"},
		} {
			starting(t, dir, args...)
		}
		if code, _, errs := run(t, "block", id, "exec", "/usr/bin/curl"); code != identity.ExitOK {
			t.Errorf("a plain block while the run starts: exit %d stderr %q", code, errs)
		}
	})
}

// TestALiveChangeToARunWhoseStartIsUnreadableSaysSo: a run whose first record line is complete but is not a run_start
// this tego can read (it does not decode, or it is another kind of line) will not become readable by waiting. Such a
// run was told it "is still starting" and to "try again in a few seconds" [starting], which never came true (the
// review's S1). It is now refused [start-unreadable], in words that say the line cannot be read, with no "yet" and no
// "try again", and still never Locked; nothing is written. An empty ledger and a first line still being written (no
// newline yet, which does not decode) are still starting.
func TestALiveChangeToARunWhoseStartIsUnreadableSaysSo(t *testing.T) {
	noTerminal(t, false, "")
	gapLine := func(t *testing.T, dir string) string {
		first, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
		if err != nil {
			t.Fatal(err)
		}
		start, err := record.Decode(bytes.SplitN(first, []byte("\n"), 2)[0])
		if err != nil || start.Kind != record.KindRunStart {
			t.Fatalf("the stand-in run's first line: %v", err)
		}
		gap := `{"v":1,"seq":0,"id":"` + strings.Repeat("0", 64) + `","prev":"","ts":"2026-10-27T12:00:00Z","mono_ns":1,"run":"` +
			start.Run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"gap","source":"supervisor","what":"record","why":"x"}`
		if e, err := record.Decode([]byte(gap)); err != nil || e.Kind == record.KindRunStart {
			t.Fatalf("the stand-in gap line: %v", err)
		}
		return gap
	}
	changes := []struct {
		mcp  bool
		args func(id string) []string
	}{
		{true, func(id string) []string { return []string{"mcp", "allow", "--yes", id, "files", "delete_file"} }},
		{false, func(id string) []string { return []string{"route", "set", "--yes", id, "anthropic", "corp"} }},
		{false, func(id string) []string { return []string{"lift", id, "net", "127.0.0.1:9", "--yes"} }},
		{false, func(id string) []string { return []string{"grant", id, "net", "127.0.0.1:9", "--for", "5m", "--yes"} }},
		{false, func(id string) []string { return []string{"restore", id, "net", "127.0.0.1:9"} }},
		{false, func(id string) []string { return []string{"block", id, "exec", "/usr/bin/curl", "--for", "5m"} }},
		{false, func(id string) []string { return []string{"block", id, "read", "/etc/hostname"} }},
	}
	for name, c := range map[string]struct {
		text       func(gap string) string
		unreadable bool
	}{
		"not json":         {func(string) string { return "{\n" }, true},
		"not a run_start":  {func(gap string) string { return gap + "\n" }, true},
		"empty":            {func(string) string { return "" }, false},
		"half-written":     {func(string) string { return `{"v":1,"seq":0,"id":"` }, false},
		"half-written gap": {func(gap string) string { return gap[:len(gap)-1] }, false},
	} {
		t.Run(name, func(t *testing.T) {
			for _, ch := range changes {
				var dir, id string
				if ch.mcp {
					dir, id = mcpRun(t, true)
				} else {
					dir, id = routedRun(t)
				}
				text, args := c.text(gapLine(t, dir)), ch.args(id)
				events := filepath.Join(dir, ledger.EventsFile)
				if err := os.WriteFile(events, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
				code, out, errs := run(t, args...)
				ok := code == identity.ExitFinding && !strings.Contains(errs, "Locked") && !strings.Contains(errs, "older tego")
				if c.unreadable {
					ok = ok && strings.Contains(errs, "[start-unreadable]") && strings.Contains(errs, "first record line") &&
						!strings.Contains(errs, "try again") && !strings.Contains(errs, " yet") && !strings.Contains(errs, "[starting]")
				} else {
					ok = ok && strings.Contains(errs, "[starting]") && strings.Contains(errs, "try again in a few seconds")
				}
				if !ok {
					t.Errorf("%v: exit %d stdout %q stderr %q", args, code, out, errs)
				}
				for _, f := range []string{mcptools.FileName, modelroutes.FileName, liveblock.FileName} {
					if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
						t.Errorf("%v wrote %s: %v", args, f, err)
					}
				}
				if b, _ := os.ReadFile(events); string(b) != text {
					t.Errorf("%v wrote the run's ledger: %q", args, b)
				}
			}
		})
	}
}
