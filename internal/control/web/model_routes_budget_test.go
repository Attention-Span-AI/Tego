// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/routeact"
)

// routeRequests appends n seeded lines to the live harm run (routesFixture): mostly file and net lines, and the
// ssl_request lines of its two models[] endpoints, each by a route its contract declares or by one it does not
// (corp, local, direct, the unmatched "stray"), with three route changes. It returns how many requests went
// by each route of api.anthropic.com:443, as the lines say.
func routeRequests(t testing.TB, root string, n int) map[string]int {
	t.Helper()
	rng := rand.New(rand.NewPCG(219, 7))
	f, err := os.OpenFile(filepath.Join(root, harmRun, "events.jsonl"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	want := map[string]int{}
	t0 := time.Date(2026, 10, 25, 13, 0, 0, 0, time.UTC)
	ssl := func(provider, host, route, backend string) string {
		return fmt.Sprintf(`"endpoint":"%s","method":"POST","path":"/v1/messages","host":"%s","size":1,"route":{"name":"%s","authority":"%s"}`,
			provider, host, route, backend)
	}
	for seq := 7; seq < 7+n; seq++ {
		ts := t0.Add(time.Duration(seq) * time.Millisecond)
		var l string
		switch k := rng.IntN(100); {
		case seq == 100 || seq == 400 || seq == 590: // three route changes, wherever the run is cut
			l = line(harmRun, "demo-harm", seq, ts, "gap", `"what":"enforce","why":"model-route-changed","model_route":{"model":"api.anthropic.com:443","route":"corp","authority":"llm-proxy.corp.example:8443","by":"uid:1 pid:2 cli","serial":1,"at":"2026-10-25T13:00:00Z"}`)
		case k < 55:
			l = line(harmRun, "demo-harm", seq, ts, "fs", fmt.Sprintf(`"verdict":"allow","op":"open","path":"/home/u/proj/f%d.go","flags":0`, rng.IntN(500)))
		case k < 62:
			l = line(harmRun, "demo-harm", seq, ts, "net", `"verdict":"allow","rule":"net[tcp://api.anthropic.com:443]","proto":"tcp","dst":"160.79.104.10:443","host":"api.anthropic.com"`)
		case k < 77:
			l = line(harmRun, "demo-harm", seq, ts, "ssl_request", ssl("anthropic", "api.anthropic.com", "direct", "api.anthropic.com:443"))
			want["direct"]++
		case k < 87:
			l = line(harmRun, "demo-harm", seq, ts, "ssl_request", ssl("anthropic", "API.Anthropic.com", "corp", "llm-proxy.corp.example:8443"))
			want["corp"]++
		case k < 92:
			l = line(harmRun, "demo-harm", seq, ts, "ssl_request", ssl("anthropic", "api.anthropic.com", "local", "127.0.0.1:11434"))
			want["local"]++
		case k < 95:
			l = line(harmRun, "demo-harm", seq, ts, "ssl_request", ssl("anthropic", "api.anthropic.com", "stray", "elsewhere.example:443")) // no entry: left out
		case k < 99:
			l = line(harmRun, "demo-harm", seq, ts, "ssl_request", ssl("openai", "api.openai.com", "direct", "api.openai.com:443")) // an endpoint with no routes
		default:
			l = line(harmRun, "demo-harm", seq, ts, "fs", `"verdict":"allow","op":"stat","path":"/usr/lib/libc.so.6"`)
		}
		if _, err := f.WriteString(l); err != nil {
			t.Fatal(err)
		}
	}
	return want
}

// routeRow is one route of the page's first endpoint with the requests it shows.
var routeRow = regexp.MustCompile(`(?s)<span class="mono">(direct|corp|local)</span>.{0,900}?Requests </span>([0-9,]+)</span>`)

// changesLine is the page's count of the run's route changes.
var changesLine = regexp.MustCompile(`Changes in this run \(([0-9]+)\)`)

// routesPage is the Model routes page of the harm run, warm: the requests it shows per route and its changes.
func routesPage(t *testing.T, s *Server, c *http.Cookie) (map[string]int, int, string) {
	t.Helper()
	body := get(t, s, c, "/routes?run="+harmRun)
	got := map[string]int{}
	for _, m := range routeRow.FindAllStringSubmatch(body, -1) {
		n, _ := strconv.Atoi(strings.ReplaceAll(m[2], ",", ""))
		got[m[1]] = n
	}
	changes := 0
	if m := changesLine.FindStringSubmatch(body); m != nil {
		changes, _ = strconv.Atoi(m[1])
	}
	return got, changes, body
}

// TestRoutesPageCountsWithoutWalkingTheLedger (C219): the Model routes page answers a run's request counts and route
// changes from what the read model folded as it read the lines, exactly (the counts the lines hold, and the walk of
// the ledger gives), and a refresh costs the same on a run of 600 lines and of 24,000: no work per line. The page
// used to walk the whole ledger, decoding every ssl_request line and every gap line, on each refresh.
func TestRoutesPageCountsWithoutWalkingTheLedger(t *testing.T) {
	type result struct {
		lines  int
		allocs float64
	}
	var res []result
	for _, lines := range []int{600, 24000} {
		root := routesFixture(t)
		want := routeRequests(t, root, lines)
		s := newServer(t, root)
		c := login(t, s)
		holdLock(t, filepath.Join(root, harmRun))
		got, changes, _ := routesPage(t, s, c)
		if !maps.Equal(got, want) {
			t.Fatalf("%d lines: the page shows %v requests per route, the lines hold %v", lines, got, want)
		}
		// The walk the page used to make is the same count, route by route.
		st, err := routeact.New(root).State(harmRun)
		if err != nil {
			t.Fatal(err)
		}
		walked := map[string]int{}
		for _, o := range st.Models[0].Options {
			walked[o.Name] = o.Requests
		}
		if !maps.Equal(got, walked) || changes != len(st.Models[0].Changes) || changes == 0 {
			t.Errorf("%d lines: the page shows %v and %d changes; the walk of the ledger gives %v and %d", lines, got, changes, walked, len(st.Models[0].Changes))
		}
		a := testing.AllocsPerRun(5, func() { routesPage(t, s, c) })
		res = append(res, result{lines, a})
		t.Logf("%d lines: %.0f allocations per refresh", lines, a)
	}
	// The same page on forty times the lines allocates the same few objects (a few more for wider numbers).
	if small, big := res[0], res[1]; big.allocs > small.allocs*1.05+100 {
		t.Errorf("a refresh allocates %.0f objects on %d lines and %.0f on %d: the page does work per line", small.allocs, small.lines, big.allocs, big.lines)
	}
}
