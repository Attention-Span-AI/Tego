// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/modelroute"
)

func sslLine(run string, seq int, t0 time.Time, host, route, backend string) string {
	return line(run, "codex", seq, t0.Add(time.Duration(seq)*time.Millisecond), "ssl_request",
		fmt.Sprintf(`"endpoint":"anthropic","method":"POST","path":"/v1/messages","host":"%s","size":1,"route":{"name":"%s","authority":"%s"}`, host, route, backend))
}

// TestRouteFactsCoverTheWholeRun (C219): the route facts are the whole run's, folded as its lines were read, however
// many lines the read model keeps: a run of 30,000 lines whose window holds fewer still counts every request and every
// route change, and a run the index cannot answer exactly (a line it refused, more routes than it bounds) answers no.
func TestRouteFactsCoverTheWholeRun(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	const run = "r-aaaa-0001-routes"
	var ls []string
	ls = append(ls, line(run, "codex", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/p"`))
	want := map[modelroute.RouteKey]int{}
	changes := 0
	for seq := 1; seq <= 30000; seq++ {
		switch {
		case seq%5000 == 0:
			ls = append(ls, line(run, "codex", seq, t0.Add(time.Duration(seq)*time.Millisecond), "gap",
				`"what":"enforce","why":"model-route-changed","model_route":{"model":"api.anthropic.com:443","route":"corp","authority":"gw.example:8443","by":"uid:1 pid:2 cli","serial":1,"at":"2026-10-27T09:00:00Z"}`))
			changes++
		case seq%3 == 0:
			ls = append(ls, sslLine(run, seq, t0, "API.Anthropic.com", "corp", "gw.example:8443"))
			want[modelroute.RouteKey{Host: "api.anthropic.com", Provider: "anthropic", Route: "corp", Backend: "gw.example:8443"}]++
		case seq%3 == 1:
			ls = append(ls, sslLine(run, seq, t0, "api.anthropic.com", "direct", "api.anthropic.com:443"))
			want[modelroute.RouteKey{Host: "api.anthropic.com", Provider: "anthropic", Route: "direct", Backend: "api.anthropic.com:443"}]++
		default:
			ls = append(ls, line(run, "codex", seq, t0.Add(time.Duration(seq)*time.Millisecond), "fs", `"verdict":"allow","op":"stat","path":"/usr/lib/x.so"`))
		}
	}
	root := t.TempDir()
	writeRun(t, root, run, ls...)
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Find(run)
	if r == nil || r.Lines != len(ls) {
		t.Fatalf("read %v, want a run of %d lines", r, len(ls))
	}
	if !r.Cut {
		t.Fatalf("the run's window holds all %d lines: the fixture is too small to show the facts outlive the window", len(r.Events))
	}
	f, ok := r.RouteFacts()
	if !ok {
		t.Fatal("no route facts for a run the store read whole")
	}
	if len(f.Tally) != len(want) {
		t.Fatalf("tally %v, want %v", f.Tally, want)
	}
	for k, n := range want {
		if f.Tally[k] != n {
			t.Errorf("tally[%v] = %d, want %d", k, f.Tally[k], n)
		}
	}
	if len(f.Changes) != changes || changes == 0 || f.Changes[0].Route != "corp" || f.Changes[0].Model != "api.anthropic.com:443" {
		t.Errorf("changes %+v, want %d of them", f.Changes, changes)
	}

	// Past the bound of distinct routes the index says no, and so does a run with a line the reader refused.
	var many []string
	many = append(many, line("r-aaaa-0002-manyrt", "codex", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/p"`))
	for i := 1; i <= maxRouteKeys+1; i++ {
		many = append(many, sslLine("r-aaaa-0002-manyrt", i, t0, fmt.Sprintf("h%d.example", i), "direct", "x:443"))
	}
	bad := []string{line("r-aaaa-0003-badline", "codex", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/p"`),
		sslLine("r-aaaa-0003-badline", 1, t0, "api.anthropic.com", "direct", "api.anthropic.com:443"),
		line("r-aaaa-0003-badline", "codex", 2, t0, "ssl_request", `"endpoint":"anthropic","host":"api.anthropic.com","size":1,"route":5`)}
	writeRun(t, root, "r-aaaa-0002-manyrt", many...)
	writeRun(t, root, "r-aaaa-0003-badline", bad...)
	s, err = Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"r-aaaa-0002-manyrt", "r-aaaa-0003-badline"} {
		if f, ok := s.Find(id).RouteFacts(); ok {
			t.Errorf("%s: route facts %+v for a run the index cannot answer exactly", id, f)
		}
	}
}
