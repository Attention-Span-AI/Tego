// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestRegionHashStableAcrossTime (PF-4): two renders of a live page 2 s apart (and 2 min apart) with no new line
// hash every region the same, though the running run's duration so far moved: its text is a data-ck clock, which
// live.js ticks and the hash leaves out. A new line still moves the regions that show it.
func TestRegionHashStableAcrossTime(t *testing.T) {
	root := fixture(t)
	now := time.Date(2026, 10, 25, 12, 5, 0, 0, time.UTC)
	s := newServer(t, root)
	s.cfg.Now = func() time.Time { return now }
	c := login(t, s)
	for _, p := range []string{"/", "/runs", "/runs/" + harmRun, "/runs/" + harmRun + "/refusals", "/approvals"} {
		b1 := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
		for _, d := range []time.Duration{2 * time.Second, 2 * time.Minute} {
			now = now.Add(d)
			b2 := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
			h1, h2 := regionsIn(b1), regionsIn(b2)
			for n, h := range h1 {
				if h2[n] != h {
					t.Errorf("%s %v later: region %s hash moved with no new line (%s -> %s)", p, d, n, h, h2[n])
				}
			}
			if p != "/approvals" && b1 == b2 {
				t.Errorf("%s %v later: the page did not change at all; the test proves nothing", p, d)
			}
		}
		if p != "/approvals" && !strings.Contains(b1, ` data-since="`) {
			t.Errorf("%s: no ticking duration (data-since) for the running run", p)
		}
	}
	// A new line moves the Overview's Running now table (its Lines count), not Recent runs.
	before := regionsIn(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String())
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "fs", `"verdict":"allow","op":"open","path":"/p/a.txt","flags":0`))
	after := regionsIn(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String())
	if before["r-ov-live"] == after["r-ov-live"] {
		t.Error("a new line of the running run did not move Running now")
	}
	if before["r-ov-recent"] != after["r-ov-recent"] {
		t.Error("a new line of the running run moved Recent runs, which lists only runs not running")
	}
}

// TestHashRegionClock: hashRegion leaves out exactly a data-ck clock's text.
func TestHashRegionClock(t *testing.T) {
	a := []byte(`<td><span class="ck" data-since="x" data-ck>3 m 2 s</span></td><td>7</td>`)
	b := []byte(`<td><span class="ck" data-since="x" data-ck>3 m 9 s</span></td><td>7</td>`)
	c := []byte(`<td><span class="ck" data-since="x" data-ck>3 m 9 s</span></td><td>8</td>`)
	d := []byte(`<td><span class="ck" data-since="y" data-ck>3 m 2 s</span></td><td>7</td>`)
	if hashRegion(a) != hashRegion(b) {
		t.Error("a clock's text moved the hash")
	}
	if hashRegion(b) == hashRegion(c) || hashRegion(a) == hashRegion(d) {
		t.Error("data outside the clock's text did not move the hash")
	}
	if e := []byte(`<p>3 m 2 s</p>`); hashRegion(e) == hashRegion([]byte(`<p>3 m 9 s</p>`)) {
		t.Error("text that is not a marked clock was left out")
	}
	if hashRegion([]byte(`<b data-ck>open`)) != hashRegion([]byte(`<b data-ck>other`)) {
		t.Error("a clock running to the end of the region is not left out")
	}
}

// TestLayoutTwinSamePage: a full page placed through the layout twin (each region rendered once) is byte for byte
// the page the layout renders when it executes every region again.
func TestLayoutTwinSamePage(t *testing.T) {
	root := fixture(t)
	s := newServer(t, root)
	c := login(t, s)
	ps, err := parsedPages()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/runs", "/runs/" + harmRun, "/runs/" + harmRun + "/receipt", "/logs", "/approvals", "/rules", "/rules/new"} {
		got := do(s, "GET", p, "127.0.0.1:8484", c).Body.Bytes()
		// The same page through the original set: swap the twins out for this one request.
		saved := ps.twins
		ps.twins = nil
		want := do(s, "GET", p, "127.0.0.1:8484", c).Body.Bytes()
		ps.twins = saved
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the twin's page differs from the layout's own (%d vs %d bytes)", p, len(got), len(want))
		}
		if len(got) < 1000 || !bytes.Contains(got, []byte("</html>")) || bytes.IndexByte(got, 0) >= 0 {
			t.Errorf("%s: not a whole page (%d bytes), or a region placeholder left in it", p, len(got))
		}
	}
}

// pagingFixture is the fixture plus n ended runs started a minute apart before it.
func pagingFixture(t *testing.T, n int) string {
	t.Helper()
	root := fixture(t)
	t0 := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	for i := range n {
		id := fmt.Sprintf("r-aaaaaaaa-%013d-endedx", 100+i)
		ts := t0.Add(time.Duration(i) * time.Minute)
		ls := line(id, "old-agent", 0, ts, "run_start", `"tier":"landlock","command":["sh","x"]`) +
			line(id, "old-agent", 1, ts.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`)
		if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(ls), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var rowKeyRe = regexp.MustCompile(`<tr role="row" data-k="([^"]+)"`)

// regionBody is region name's HTML in page b: from its wrapper to the next region's.
func regionBody(b, name string) string {
	i := strings.Index(b, `data-live="`+name+`"`)
	if i < 0 {
		return ""
	}
	b = b[i:]
	if j := strings.Index(b[1:], `data-live="`); j >= 0 {
		b = b[:j+1]
	}
	return b
}

// TestRunsPaging (PF-4): Runs lists the running runs first, in their own region, then 100 others newest first, with
// an Older runs link that pages by run id; the counts stay the whole ledger's, and the state filter keeps paging.
func TestRunsPaging(t *testing.T) {
	root := pagingFixture(t, 205)
	s := newServer(t, root)
	c := login(t, s)
	b := do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String()
	live, rest := rowKeyRe.FindAllStringSubmatch(regionBody(b, "r-runs-live"), -1), rowKeyRe.FindAllStringSubmatch(regionBody(b, "r-runs-table"), -1)
	if len(live) != 1 || live[0][1] != harmRun {
		t.Fatalf("running rows: %v, want the harm run alone", live)
	}
	if len(rest) != runsPage || rest[0][1] != cleanRun {
		t.Fatalf("first page: %d rows starting %v, want %d starting with the newest ended run", len(rest), rest[:1], runsPage)
	}
	if !strings.Contains(b, "<h1>207 runs</h1>") || !strings.Contains(b, "Ended 206") {
		t.Errorf("the counts are not the whole ledger's")
	}
	if !strings.Contains(b, "runs 1–100 of the 206 not running") {
		t.Errorf("first page does not say where it is")
	}
	older := regexp.MustCompile(`<a class="btn" href="(/runs\?before=[^"]+)">Older runs</a>`).FindStringSubmatch(b)
	if older == nil {
		t.Fatal("no Older runs link")
	}
	u, err := url.Parse(strings.ReplaceAll(older[1], "&amp;", "&"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("before") != rest[len(rest)-1][1] {
		t.Errorf("Older runs pages after %q, want the page's last run %q", u.Query().Get("before"), rest[len(rest)-1][1])
	}
	b2 := do(s, "GET", u.String(), "127.0.0.1:8484", c).Body.String()
	live2, rest2 := rowKeyRe.FindAllStringSubmatch(regionBody(b2, "r-runs-live"), -1), rowKeyRe.FindAllStringSubmatch(regionBody(b2, "r-runs-table"), -1)
	if len(live2) != 0 || len(rest2) != runsPage || rest2[0][1] == rest[len(rest)-1][1] {
		t.Errorf("second page: %d running, %d others, first %v", len(live2), len(rest2), rest2[:1])
	}
	if !strings.Contains(b2, `>Newest runs</a>`) || !strings.Contains(b2, "runs 101–200 of the 206") {
		t.Error("second page has no way back to the newest, or does not say where it is")
	}
	b3 := do(s, "GET", "/runs?before="+url.QueryEscape(rest2[len(rest2)-1][1]), "127.0.0.1:8484", c).Body.String()
	if n := len(rowKeyRe.FindAllStringSubmatch(regionBody(b3, "r-runs-table"), -1)); n != 6 || strings.Contains(b3, ">Older runs</a>") {
		t.Errorf("last page: %d rows (want 6) or an Older link", n)
	}
	// A cursor the ledger no longer holds starts at the newest page; the state filter pages too.
	if b := do(s, "GET", "/runs?before=r-aaaaaaaa-0000000009999-gonexx", "127.0.0.1:8484", c).Body.String(); !strings.Contains(regionBody(b, "r-runs-live"), harmRun) {
		t.Error("an unknown cursor did not start at the newest page")
	}
	bs := do(s, "GET", "/runs?state=ended", "127.0.0.1:8484", c).Body.String()
	if strings.Contains(bs, `data-k="`+harmRun+`"`) || !strings.Contains(bs, "/runs?before=") || !strings.Contains(bs, "state=ended") {
		t.Error("state=ended lists the running run or loses its filter when paging")
	}
	// The Compare chooser lists the newest maxPick runs and the pair, not every run.
	if n := strings.Count(regexp.MustCompile(`(?s)<select class="select" name="a">.*?</select>`).FindString(b), "<option "); n > maxPick+2 {
		t.Errorf("the chooser lists %d runs, want at most %d", n, maxPick+2)
	}
}

// TestOverviewRecentNotRunning: Recent runs leaves out a running run (it is under Running now), and the Overview's
// panels render nothing, with the empty state, when the ledger has no run.
func TestOverviewRecentNotRunning(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	b := do(s, "GET", "/", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(regionBody(b, "r-ov-live"), `data-k="`+harmRun+`"`) || strings.Contains(regionBody(b, "r-ov-recent"), `data-k="`+harmRun+`"`) {
		t.Error("the running run is not under Running now alone")
	}
	if !strings.Contains(regionBody(b, "r-ov-recent"), `data-k="`+cleanRun+`"`) {
		t.Error("Recent runs lacks the ended run")
	}
	e := newServer(t, t.TempDir())
	ec := login(t, e)
	eb := do(e, "GET", "/", "127.0.0.1:8484", ec).Body.String()
	if !strings.Contains(eb, "No runs yet") || strings.Contains(eb, `id="h-running"`) || strings.Contains(eb, `id="h-recent"`) {
		t.Error("an empty ledger's Overview shows its panels, or not its empty state")
	}
}

// TestRegionCache: a second region ask for the same address, regions and live state within regionTTL is answered
// from the first render; a new line, a POST, or the time running out answers it from the handler again.
func TestRegionCache(t *testing.T) {
	var rc regionCache
	t0 := time.Now()
	st := liveState{Rev: "r1", Sig: "s1"}
	k := cacheKey("/", "", map[string]string{"r-top": "a", "r-nav": "b"}, st)
	if k != cacheKey("/", "", map[string]string{"r-nav": "x", "r-top": "y"}, st) {
		t.Error("the key depends on the hashes shown or their order, not only on the regions asked for")
	}
	if k == cacheKey("/", "", map[string]string{"r-top": "a"}, st) || k == cacheKey("/", "", map[string]string{"r-top": "a", "r-nav": "b"}, liveState{Rev: "r2", Sig: "s1"}) ||
		k == cacheKey("/runs", "", map[string]string{"r-top": "a", "r-nav": "b"}, st) {
		t.Error("another region set, revision or address shares the key")
	}
	_, gen, hit := rc.get(k, t0)
	if hit {
		t.Fatal("an empty cache hit")
	}
	rc.put(k, regionEntry{at: t0, gen: gen, status: http.StatusOK})
	if _, _, hit := rc.get(k, t0.Add(regionTTL/2)); !hit {
		t.Error("no hit within regionTTL")
	}
	if _, _, hit := rc.get(k, t0.Add(regionTTL)); hit {
		t.Error("a hit after regionTTL")
	}
	_, gen, _ = rc.get(k, t0)
	rc.bump() // a POST while that render ran
	rc.put(k, regionEntry{at: t0, gen: gen, status: http.StatusOK})
	if _, _, hit := rc.get(k, t0); hit {
		t.Error("a render begun before a POST was kept after it")
	}

	// Through the server: two viewers' asks at the same state get the same regions; a new line answers anew.
	root := fixture(t)
	s := newServer(t, root)
	c := login(t, s)
	have := regionsIn(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String())
	stale := map[string]string{}
	for n := range have {
		stale[n] = "0"
	}
	a1 := doRegions(s, "/", "127.0.0.1:8484", c, headerOf(stale)).Body.String()
	a2 := doRegions(s, "/", "127.0.0.1:8484", c, headerOf(stale)).Body.String()
	if a1 == "" || a1 != a2 {
		t.Errorf("two asks at the same state differ (%d vs %d bytes)", len(a1), len(a2))
	}
	if got := doRegions(s, "/", "127.0.0.1:8484", c, headerOf(have)).Body.String(); got != "" {
		t.Errorf("a viewer showing the current hashes was sent regions from the cache: %q", got)
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 4, 0, 0, time.UTC), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/cache-miss"`))
	if a3 := doRegions(s, "/", "127.0.0.1:8484", c, headerOf(stale)).Body.String(); !strings.Contains(a3, "/p/cache-miss") {
		t.Error("a new line was answered from the cache")
	}
}

// TestLostRunDoesNotTick: a lost run has stopped, so its duration carries no data-since for live.js to count up: the
// Runs row kept a lost run's time growing for as long as the page stayed open.
func TestLostRunDoesNotTick(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	r := &ledgerview.Run{Start: t0, Last: t0.Add(90 * time.Second)}
	if ck := ckOf(r, t0.Add(1000*time.Hour)); ck.Ticks || ck.D != 90*time.Second {
		t.Errorf("a lost run: ticks %v, %s", ck.Ticks, ck.D)
	}
	r.Live = true
	if ck := ckOf(r, t0.Add(time.Hour)); !ck.Ticks || ck.D != time.Hour {
		t.Errorf("a running run: ticks %v, %s", ck.Ticks, ck.D)
	}
}
