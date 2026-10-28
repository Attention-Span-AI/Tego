// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

var fragRe = regexp.MustCompile(`<template data-live="([^"]+)" data-h="([0-9a-f]{16})">`)

// regionAsk is one region request for page showing have, answered by s; like live.js, it takes each region the
// answer brings into have.
func regionAsk(t *testing.T, s *Server, c *http.Cookie, page string, have map[string]string) int {
	t.Helper()
	w := doRegions(s, page, "127.0.0.1:8484", c, headerOf(have))
	if w.Code == http.StatusNoContent && w.Body.Len() != 0 {
		t.Fatalf("%s: a 204 with a body %q", page, w.Body.String())
	}
	for _, m := range fragRe.FindAllStringSubmatch(w.Body.String(), -1) {
		have[m[1]] = m[2]
	}
	return w.Code
}

// TestRegionUnchanged204: a run page that asks again with the hashes it was answered with gets 204 while nothing it
// shows moved, even as another run writes lines; its own run's lines, a reference run's lines, its live blocks, the
// launcher's pause mark, a rule change, a new ask, its clock while it runs and a page showing other hashes each get
// the handler's answer. Other pages are always answered by their handler.
func TestRegionUnchanged204(t *testing.T) {
	root := fixture(t)
	now := time.Date(2026, 10, 25, 12, 5, 0, 0, time.UTC)
	s := newServer(t, root)
	s.cfg.Now = func() time.Time { return now }
	c := login(t, s)
	page := "/runs/" + harmRun
	have := regionsIn(do(s, "GET", page, "127.0.0.1:8484", c).Body.String())
	if got := regionAsk(t, s, c, page, have); got != http.StatusOK {
		t.Fatalf("first region ask: %d, want 200 (nothing kept yet)", got)
	}
	if got := regionAsk(t, s, c, page, have); got != http.StatusNoContent {
		t.Fatalf("second region ask, nothing moved: %d, want 204", got)
	}

	// Another run writes a line: the root's revision moves, this page's key does not.
	t0 := time.Date(2026, 10, 25, 12, 0, 3, 0, time.UTC)
	appendLine(t, root, cleanRun, line(cleanRun, "demo-clean", 3, t0, "fs", `"verdict":"allow","op":"open","path":"out/more.txt","flags":577`))
	if got := regionAsk(t, s, c, page, have); got != http.StatusNoContent {
		t.Errorf("another run moved: %d, want 204", got)
	}
	// A page showing other hashes (one left behind) is answered in full.
	stale := map[string]string{}
	for n, h := range have {
		stale[n] = h
	}
	stale["r-run-hl"] = "0000000000000000"
	if got := regionAsk(t, s, c, page, stale); got != http.StatusOK {
		t.Errorf("a page with an old region: %d, want 200", got)
	}

	moved := func(what string, change func()) {
		t.Helper()
		regionAsk(t, s, c, page, have) // settle: keep the current answer
		if got := regionAsk(t, s, c, page, have); got != http.StatusNoContent {
			t.Fatalf("before %s: %d, want 204", what, got)
		}
		change()
		if got := regionAsk(t, s, c, page, have); got != http.StatusOK {
			t.Errorf("after %s: %d, want 200 (the handler's answer)", what, got)
		}
	}
	moved("a line of its own run", func() {
		appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "fs", `"verdict":"allow","op":"open","path":"/p/a.txt","flags":0`))
	})
	moved("a live block placed", func() {
		if err := os.WriteFile(filepath.Join(root, harmRun, "live-block.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	moved("the launcher's pause mark made", func() {
		// LIVE-PAUSE: the page offers Pause only once the run's launcher marked that it reads one.
		if err := liveblock.MarkControl(filepath.Join(root, harmRun)); err != nil {
			t.Fatal(err)
		}
	})
	moved("a rule change journaled", func() {
		// UNDO-LIVE: the timeline shows the journal's changes as rows, and a change that places no live block writes
		// no ledger line.
		p := rules.JournalPath(root)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	moved("a stop asked", func() {
		if err := os.WriteFile(filepath.Join(root, harmRun, "stop.request"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	// The wall clock alone moves nothing: the duration so far ticks in the browser, out of the hashes.
	regionAsk(t, s, c, page, have)
	now = now.Add(time.Minute)
	if got := regionAsk(t, s, c, page, have); got != http.StatusNoContent {
		t.Errorf("a minute later, no new line: %d, want 204", got)
	}

	// Overview and a line page follow the whole root: always their handler.
	for _, p := range []string{"/", "/runs/" + harmRun + "/lines/1", "/runs/" + harmRun + "/unused"} {
		h := regionsIn(do(s, "GET", p, "127.0.0.1:8484", c).Body.String())
		for i := range 2 {
			if got := regionAsk(t, s, c, p, h); got != http.StatusOK {
				t.Errorf("%s ask %d: %d, want 200", p, i, got)
			}
		}
	}
}

// TestRegionUnchanged204Reference: a watched run's page is read against the enforced run of the same program, so
// that run's lines answer it in full.
func TestRegionUnchanged204Reference(t *testing.T) {
	root := fixture(t)
	const watched = "r-aaaaaaaa-0000000000003-watchx"
	// Started with harmRun (12:01), so harmRun is its pair (ledgerview.PairOf), not cleanRun, which also runs sh.
	t0 := time.Date(2026, 10, 25, 12, 1, 0, 0, time.UTC)
	if err := os.MkdirAll(filepath.Join(root, watched), 0o755); err != nil {
		t.Fatal(err)
	}
	ls := line(watched, "demo-harm", 0, t0, "run_start", `"tier":"observe","command":["sh","agent.sh"]`) +
		line(watched, "demo-harm", 1, t0.Add(time.Second), "net", `"verdict":"allow","proto":"tcp","dst":"93.184.216.34:443","host":"example.com"`) +
		line(watched, "demo-harm", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`)
	if err := os.WriteFile(filepath.Join(root, watched, "events.jsonl"), []byte(ls), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	page := "/runs/" + watched
	have := regionsIn(do(s, "GET", page, "127.0.0.1:8484", c).Body.String())
	regionAsk(t, s, c, page, have)
	if got := regionAsk(t, s, c, page, have); got != http.StatusNoContent {
		t.Fatalf("the watched run, nothing moved: %d, want 204", got)
	}
	now := time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC)
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "fs", `"verdict":"allow","op":"open","path":"/p/a.txt","flags":0`))
	if got := regionAsk(t, s, c, page, have); got != http.StatusOK {
		t.Errorf("its reference run moved: %d, want 200", got)
	}
}
