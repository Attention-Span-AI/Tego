// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// budgetRoot writes a seeded ledger root under t.TempDir(): runs runs of lines lines each, the mix a Codex session
// writes (file reads and writes, secret reads and refusals with the mirror a refused action leaves, connects to the
// model's host and to others, programs run and refused, name lookups) from a fixed seed, so the same call is the same
// ledger line for line. Nothing in it is read from the machine.
func budgetRoot(t testing.TB, runs, lines int) string {
	t.Helper()
	root := t.TempDir()
	rng := rand.New(rand.NewPCG(40, 19528))
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	for k := range runs {
		id := fmt.Sprintf("r-aaaaaaaa-%013d-budget", k+1)
		var b strings.Builder
		ts := t0.Add(time.Duration(k) * time.Hour)
		seq := 0
		add := func(kind, extra string) {
			b.WriteString(line(id, "codex", seq, ts, kind, extra))
			seq++
		}
		add("run_start", `"tier":"landlock","command":["codex","exec","the task"],"cwd":"/home/u/proj"`)
		for seq < lines {
			ts = ts.Add(time.Duration(rng.Int64N(int64(40*time.Millisecond)) + 1))
			f := rng.IntN(5000)
			switch n := rng.IntN(100); {
			case n < 45:
				add("fs", fmt.Sprintf(`"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/home/u/proj/src/f%d.go","flags":0`, f))
			case n < 52:
				add("fs", fmt.Sprintf(`"rule":"fs.write[./]","verdict":"allow","op":"open","path":"/home/u/proj/out/o%d.txt","flags":577`, f%400))
			case n < 55:
				add("fs", `"rule":"fs.deny_read[/home/u/.ssh/]","verdict":"refused","reason":"read-denied","op":"open","path":"/home/u/.ssh/id_rsa"`)
				add("refused", `"rule":"fs.deny_read[/home/u/.ssh/]","reason":"read-denied","op":"open","target":"/home/u/.ssh/id_rsa"`)
			case n < 65:
				add("net", `"rule":"net[tcp://chatgpt.com:443]","verdict":"allow","dst":"104.18.32.47:443","host":"chatgpt.com","proto":"tcp"`)
			case n < 69:
				add("net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"104.18.32.47:65535"`)
				add("refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:65535"`)
			case n < 72:
				add("net", `"rule":"net.resolver","verdict":"allow","dst":"127.0.0.53:53","proto":"udp"`)
			case n < 82:
				add("exec", fmt.Sprintf(`"rule":"exec[git]","verdict":"allow","path":"/usr/bin/git","argv":["git","status","-%d"],"exec_id":"%s/%d/%d"`, f%5, id, 1000+f, 10+f))
			case n < 84:
				add("refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/lsb_release"`)
			default:
				add("fs", fmt.Sprintf(`"rule":"unmatched","verdict":"observed","op":"stat","path":"/usr/lib/x86_64-linux-gnu/l%d.so"`, f%300))
			}
		}
		add("run_end", `"reason":"exit","exit_code":0`)
		if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// logsBudgetPages are the pages of the budget: the Logs page and the queries a person makes there.
var logsBudgetPages = []string{
	"/logs",
	"/logs?verdict=refused",
	"/logs?where=" + url.QueryEscape("verdict:refused -kind:refused"),
	// since:24h is pinned to the clock by a redirect to this form, which is the page a person's refresh then asks.
	"/logs?span=" + url.QueryEscape("24h@2026-10-24T12:05:00") + "&where=" + url.QueryEscape("host:chatgpt.com since:2026-10-24T12:05:00"),
	"/logs?q=.ssh",
	"/logs?where=" + url.QueryEscape("path:~/.ssh"),
	"/logs?group=process",
	"/logs?group=target&verdict=refused",
	"/logs?group=rule&where=" + url.QueryEscape("prog:codex"),
	"/logs?group=rule&where=" + url.QueryEscape("prog:git"),
	"/logs/rows?after=" + url.QueryEscape("0.r.0"),
}

// warmBytes is what one call of fn allocates, as the least of n calls. TotalAlloc is the whole process's: whatever else
// allocates while fn runs (the runtime's pools refilling after a collection, a goroutine another test left behind)
// adds to a sample and never takes from it, so the least sample is the cost of fn itself, and a structure fn builds
// per line is in every sample (one sample of /logs?group=process was 221 bytes over the band, which a ledger's
// real growth, about 14 bytes a line from the fold's row list, leaves 84 KB of).
func warmBytes(n int, fn func()) uint64 {
	best := ^uint64(0)
	for range n {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		best = min(best, after.TotalAlloc-before.TotalAlloc)
	}
	return best
}

var warmSink []byte

// TestWarmBytesIgnoresAllocationFromOutsideTheCall: an allocation another goroutine makes inside some of the samples
// does not move the figure, and one the call makes itself in every sample does.
func TestWarmBytesIgnoresAllocationFromOutsideTheCall(t *testing.T) {
	const own, other = 1 << 20, 1 << 19
	calls := 0
	fn := func() {
		warmSink = make([]byte, own)
		calls++
		if calls%3 != 0 { // the stray allocation lands in two samples of three
			warmSink = make([]byte, other)
		}
	}
	got := warmBytes(5, fn)
	if got < own || got > own+other/2 {
		t.Errorf("warmBytes = %d, want about %d: the stray allocation was counted", got, own)
	}
	if got := warmBytes(5, func() { warmSink = make([]byte, own+other) }); got < own+other {
		t.Errorf("warmBytes = %d, want at least %d: the call's own allocation was dropped", got, own+other)
	}
}

// TestLogsWarmBudget holds the Logs page's warm budget (40 ms on the demo ledger of 19,528 lines, 5 runs; docs/DASHBOARD.md,
// "Read model") by what makes it true, counted, on a seeded ledger every runner has. A warm page is built from what a
// version of each run memoized (the folded rows, the counts, the facets, the haystacks of a text search), so it shows
// the same hundred rows and the same counts whatever the ledger's size and builds nothing per line: its allocations
// and the bytes it allocates are the same on a ledger of 9,000 lines and of 36,000, and its allocations under a
// ceiling no page of the budget set comes near. A page that walked or decoded the ledger on each refresh, or built a
// haystack, a fold or a process index again, would allocate in proportion to the lines and fail here on any machine, which a wall-clock figure on a shared runner cannot say. Every page of the set answers 200.
func TestLogsWarmBudget(t *testing.T) {
	if raceEnabled {
		// The race detector's instrumentation changes how many objects and bytes the same code allocates: a grouped
		// page grew from 6.65 MB to 7.75 MB between the two ledgers in a race run on a hosted runner, over a bound
		// measured without it. The budgets hold in the plain unit run of every pull request.
		t.Skip("allocation budgets are measured without the race detector")
	}
	const slack = 200         // a few objects more for wider numbers on the bigger ledger
	const byteSlack = 1 << 18 // and a quarter of a megabyte
	const ceiling = 150_000   // allocations a warm page may cost (103,000 measured, the plain page's 100 rows with their facets)
	type ledger struct {
		lines int
		s     *Server
		c     *http.Cookie
	}
	var ledgers []ledger
	for _, perRun := range []int{3000, 12000} {
		s := newServer(t, budgetRoot(t, 3, perRun))
		ledgers = append(ledgers, ledger{3 * perRun, s, login(t, s)})
	}
	for _, p := range logsBudgetPages {
		var allocs []float64
		var bytes []uint64
		for _, l := range ledgers {
			w := do(l.s, "GET", p, "127.0.0.1:8484", l.c)
			if w.Code != http.StatusOK {
				t.Fatalf("%s on %d lines: %d %s", p, l.lines, w.Code, w.Body.String())
			}
			if w.Body.Len() == 0 {
				t.Fatalf("%s on %d lines: an empty page", p, l.lines)
			}
			do(l.s, "GET", p, "127.0.0.1:8484", l.c) // warm: the memos of this version of each run are built
			allocs = append(allocs, testing.AllocsPerRun(3, func() { do(l.s, "GET", p, "127.0.0.1:8484", l.c) }))
			bytes = append(bytes, warmBytes(5, func() { do(l.s, "GET", p, "127.0.0.1:8484", l.c) }))
		}
		t.Logf("%-120s %7.0f allocations on %d lines, %7.0f on %d; %d bytes, %d", p, allocs[0], ledgers[0].lines, allocs[1], ledgers[1].lines, bytes[0], bytes[1])
		if allocs[1] > allocs[0]*1.10+slack {
			t.Errorf("%s: a warm page allocated %.0f objects on %d lines and %.0f on %d: it does work per line", p, allocs[0], ledgers[0].lines, allocs[1], ledgers[1].lines)
		}
		if float64(bytes[1]) > float64(bytes[0])*1.10+byteSlack {
			t.Errorf("%s: a warm page allocated %d bytes on %d lines and %d on %d: it builds something per line", p, bytes[0], ledgers[0].lines, bytes[1], ledgers[1].lines)
		}
		if allocs[1] > ceiling {
			t.Errorf("%s: a warm page allocated %.0f objects, ceiling %d", p, allocs[1], ceiling)
		}
	}
}

// TestGroupedLogsWithNoMatchIsEmptyNotAnError: a grouped Logs page whose query matches no line says so; it was a 500
// ("can't evaluate field Numbers") because the empty branch of its template read the page's scope by a name the
// template had rebound.
func TestGroupedLogsWithNoMatchIsEmptyNotAnError(t *testing.T) {
	s := newServer(t, budgetRoot(t, 1, 400))
	c := login(t, s)
	for _, p := range []string{"/logs?group=rule&where=" + url.QueryEscape("prog:nosuchprogram"), "/logs?group=process&q=zzzznothing", "/logs?group=target&where=" + url.QueryEscape("host:nosuch.example")} {
		w := do(s, "GET", p, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Nothing in the runs read matches these filters") {
			t.Errorf("%s: %d, want 200 saying nothing matches: %.300s", p, w.Code, w.Body.String())
		}
	}
}
