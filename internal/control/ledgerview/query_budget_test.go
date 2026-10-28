// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"os"
	"testing"
	"time"
)

// TestQueryBudget measures Logs' query plus facets on a big ledger, first and again, against the budget LG-F11 set:
// a plain query under 60 ms first and 5 ms again, any one filter under 60 ms first and 25 ms again. It needs a ledger
// root to read (read only; give it a copy) in TEGO_LOGS_BENCH_LEDGER, such as the 350,000-line synthetic one, and is
// skipped without one. TEGO_LOGS_BENCH_STRICT=1 fails a miss; otherwise each miss is logged.
func TestQueryBudget(t *testing.T) {
	root := os.Getenv("TEGO_LOGS_BENCH_LEDGER")
	if root == "" {
		t.Skip("TEGO_LOGS_BENCH_LEDGER names no ledger root to measure")
	}
	strict := os.Getenv("TEGO_LOGS_BENCH_STRICT") == "1"
	t0 := time.Now()
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("load: %d runs, %d lines, %v", len(s.Runs), s.Lines, time.Since(t0).Round(time.Millisecond))
	home := "~/.ssh"
	cases := []struct {
		name         string
		f            Filter
		first, again time.Duration
	}{
		{"plain", Filter{}, 60 * time.Millisecond, 5 * time.Millisecond},
		{"verdict:refused", Filter{Verdicts: []string{"refused"}}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"kind:exec", Filter{Kinds: []string{"exec"}}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"-kind:fs", Filter{Not: Exclude{Kinds: []string{"fs"}}}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"host:api.example.com", Filter{Hosts: []string{"api.example.com"}}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"rule:fs.*", Filter{Rules: []string{"fs.*"}}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"pid:4242", Filter{PID: 4242}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"path:" + home, Filter{PathPrefix: home}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"source:kernel", Filter{Source: "kernel"}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"since:24h", Filter{Since: time.Now().Add(-24 * time.Hour)}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"since (all)", Filter{Since: time.Unix(0, 0)}, 60 * time.Millisecond, 25 * time.Millisecond},
		// The first text search of a run builds its haystacks once per version (memo.go, D-CACHE); every later word
		// reuses them.
		{"q=.ssh (builds the haystacks)", Filter{Text: ".ssh"}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"word curl", Filter{Words: []string{"curl"}}, 60 * time.Millisecond, 25 * time.Millisecond},
		{"-word unlink", Filter{Not: Exclude{Words: []string{"unlink"}}}, 60 * time.Millisecond, 25 * time.Millisecond},
	}
	for _, c := range cases {
		f := c.f
		f.Facets = true
		a := time.Now()
		pg := s.Query(f)
		first := time.Since(a)
		a = time.Now()
		pg2 := s.Query(f)
		again := time.Since(a)
		if pg.Matched != pg2.Matched {
			t.Errorf("%s: %d then %d lines", c.name, pg.Matched, pg2.Matched)
		}
		t.Logf("%-32s %8d lines  first %7.2f ms  again %6.2f ms", c.name, pg.Matched,
			float64(first.Microseconds())/1000, float64(again.Microseconds())/1000)
		if first > c.first || again > c.again {
			msg := "%s: first %v (budget %v), again %v (budget %v)"
			if strict {
				t.Errorf(msg, c.name, first, c.first, again, c.again)
			} else {
				t.Logf("over budget: "+msg, c.name, first, c.first, again, c.again)
			}
		}
	}
	// Without facets, a warm plain page stays as cheap as before them.
	a := time.Now()
	s.Query(Filter{})
	t.Logf("plain without facets, warm: %.2f ms", float64(time.Since(a).Microseconds())/1000)
}
