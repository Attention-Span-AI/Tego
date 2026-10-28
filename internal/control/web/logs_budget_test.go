// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestLogsWarmBudget measures a warm /logs (the page with its facets) on a demo-shaped ledger against its 40 ms
// budget. It reads the ledger root in TEGO_LOGS_BENCH_DEMO (read only; give it a copy) and is skipped without one.
func TestLogsWarmBudget(t *testing.T) {
	root := os.Getenv("TEGO_LOGS_BENCH_DEMO")
	if root == "" {
		t.Skip("TEGO_LOGS_BENCH_DEMO names no ledger root to measure")
	}
	s := newServer(t, root)
	c := login(t, s)
	for _, p := range []string{
		"/logs",
		"/logs?verdict=refused",
		"/logs?where=" + url.QueryEscape("verdict:refused -kind:refused"),
		"/logs?where=" + url.QueryEscape("host:chatgpt.com since:24h"),
		"/logs?q=.ssh",
		"/logs?where=" + url.QueryEscape("path:~/.ssh"),
		"/logs?group=process",
		"/logs?group=target&verdict=refused",
		"/logs?group=rule&where=" + url.QueryEscape("prog:codex"),
		"/logs/rows?after=" + url.QueryEscape("0.r.0"),
	} {
		a := time.Now()
		w := do(s, "GET", p, "127.0.0.1:8484", c)
		first := time.Since(a)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, w.Code)
		}
		best := time.Hour
		for range 5 {
			a = time.Now()
			do(s, "GET", p, "127.0.0.1:8484", c)
			best = min(best, time.Since(a))
		}
		t.Logf("%-60s first %6.1f ms  warm %5.1f ms  %d KB", p, float64(first.Microseconds())/1000,
			float64(best.Microseconds())/1000, w.Body.Len()>>10)
		if best > 40*time.Millisecond {
			t.Errorf("%s: warm %v, budget 40 ms", p, best)
		}
	}
}
