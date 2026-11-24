// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// limitGapLine is the launcher's gap line why for a block of kind and value: an add or remove confirmed at serial, or
// an expire of the limit until.
func limitGapLine(seq int, ts time.Time, why, kind, value string, serial uint64, until time.Time) string {
	op := map[string]string{"live-block-added": "add", "live-block-removed": "remove", "live-block-expired": "expire", "live-unblock-expired": "expire"}[why]
	u := ""
	if !until.IsZero() {
		u = `,"until":"` + until.UTC().Format(time.RFC3339Nano) + `"`
	}
	return line(harmRun, "demo-harm", seq, ts, "gap", fmt.Sprintf(
		`"what":"enforce","why":"%s","live_block":{"op":"%s","kind":"%s","value":"%s","rule":"live.block[%s:%s]","by":"uid:1000 pid:9 cli","serial":%d,"at":"%s"%s}`,
		why, op, kind, value, kind, value, serial, ts.UTC().Format(time.RFC3339Nano), u))
}

// TestTimedBlockFollowsTheLaunchersClock (C215): the run page says a block's time limit passed only when the run's
// launcher recorded it. The launcher judges a limit on the wall clock and on a clock no step moves, so a wall clock
// stepped forward past the limit left the page saying "Ended" for a block the launcher still enforced, and one
// stepped back kept "in force" on a block it had ended. The page's clock is injected, so nothing sleeps.
func TestTimedBlockFollowsTheLaunchersClock(t *testing.T) {
	root := fixture(t)
	s := newServer(t, root)
	c := login(t, s)
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	now := t0
	s.cfg.Now = func() time.Time { return now }
	dir := filepath.Join(root, harmRun)
	until := t0.Add(time.Hour)
	if _, err := liveblock.Update(context.Background(), dir, harmRun, func(o *liveblock.Overlay) (bool, error) {
		_, ok, err := o.AddUntil(liveblock.KindExec, "/usr/bin/curl", liveblock.By("cli"), t0.Add(-time.Minute), until)
		return ok, err
	}); err != nil {
		t.Fatal(err)
	}
	lb, err := liveblock.Read(dir, harmRun)
	if err != nil {
		t.Fatal(err)
	}
	appendLine(t, root, harmRun, limitGapLine(7, t0.Add(-30*time.Second), "live-block-added", "exec", "/usr/bin/curl", lb.Serial, until))
	page := func() string { return f3Text(do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()) }
	abs := chipUntil(until, now)

	// Inside the limit: the absolute time with its zone, and how far away it is.
	body := page()
	for _, want := range []string{"In force since line #7", "until " + abs + " (in 60 minutes)"} {
		if !strings.Contains(body, want) {
			t.Errorf("a block inside its limit lacks %q", want)
		}
	}
	if !strings.Contains(abs, "UTC") {
		t.Errorf("the time %q does not name its zone", abs)
	}

	// The wall clock is stepped forward past the limit; the launcher has recorded nothing, so the block is in force.
	now = until.Add(2 * time.Hour)
	body = page()
	if strings.Contains(body, "Ended at") || strings.Contains(body, "Ended by its time limit") {
		t.Error("the page calls a block ended on the wall clock's word alone")
	}
	for _, want := range []string{"has passed on this clock, but the run keeps its own time", "1 block active now"} {
		if !strings.Contains(body, want) {
			t.Errorf("a block past its limit on this clock only lacks %q", want)
		}
	}

	// The launcher records the end, and the wall clock is stepped back before it: the block is ended.
	appendLine(t, root, harmRun, limitGapLine(8, until.Add(time.Second), "live-block-expired", "exec", "/usr/bin/curl", lb.Serial, until))
	now = until.Add(-30 * time.Minute)
	body = page()
	if !strings.Contains(body, "Ended at "+abs) || !strings.Contains(body, "it refuses nothing now") {
		t.Error("a block the launcher ended does not read as ended")
	}
	if strings.Contains(body, "In force since line #7") || strings.Contains(body, "1 block active now") {
		t.Error("a block the launcher ended still reads as in force or active")
	}
}

// TestTimeLimitFormsCarryTheBrowsersZone (C216): every form with a time limit has the field the browser's script
// fills with its own zone, so an "until" typed there is read in the zone the person typed it in. Nothing filled it
// before, so the dashboard read it in its own zone (another system's browser, behind the relay, typed another one).
func TestTimeLimitFormsCarryTheBrowsersZone(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	for _, page := range []string{"/runs/" + adjRun, "/rules?run=" + adjRun} {
		body := do(s, "GET", page, "127.0.0.1:8484", c).Body.String()
		forms := strings.Count(body, `<select class="select" name="for">`)
		if forms == 0 {
			t.Fatalf("%s has no time limit select", page)
		}
		if n := strings.Count(body, `<input type="hidden" name="tz" value="" data-zone>`); n != forms {
			t.Errorf("%s has %d time limit forms and %d zone fields", page, forms, n)
		}
	}
	js, err := assets.ReadFile("static/live.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"formdata", "getTimezoneOffset", "[data-zone]"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("live.js does not fill the zone field (%q)", want)
		}
	}
}

// TestUntilIsEchoedInTheZoneItWasTyped (C216): a time limit typed in the browser's zone is read in it and said back in
// it, naming it, with how far away it is, so the person sees the time they typed and not the dashboard machine's.
func TestUntilIsEchoedInTheZoneItWasTyped(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	click := time.Now()
	fixLiveNow(t, click)
	target := click.Add(12 * time.Hour)
	type zone struct {
		tz   string // what getTimezoneOffset says
		loc  *time.Location
		name string
	}
	for _, z := range []zone{
		{"-540", time.FixedZone("", 9*3600), "+0900"},  // Tokyo
		{"240", time.FixedZone("", -4*3600), "-0400"},  // New York in summer time
		{"", time.Local, target.Local().Format("MST")}, // no script: the dashboard's own zone
	} {
		typed := target.In(z.loc).Format("2006-01-02T15:04")
		v := url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {"/bin/tz" + z.tz}, "for": {"until"}, "until": {typed}}
		if z.tz != "" {
			v.Set("tz", z.tz)
		}
		b := html.UnescapeString(follow(t, s, c, post(s, "/runs/"+adjRun+"/block", v, own, "", c)))
		want := "It lasts until " + target.In(z.loc).Truncate(time.Minute).Format("Mon 2 Jan 15:04") + " " + z.name + " (in 12 hours)."
		if !strings.Contains(b, want) {
			t.Errorf("tz %q: the flash lacks %q", z.tz, want)
		}
		o, err := liveblock.Read(dir, adjRun)
		if err != nil {
			t.Fatal(err)
		}
		e, ok := o.Find(liveblock.KindExec, "/bin/tz"+z.tz)
		if !ok || !e.Until.Equal(target.Truncate(time.Minute)) {
			t.Errorf("tz %q: the block %+v ends %v, want %v (the time typed, read in the zone it was typed in)", z.tz, e, e.Until, target.Truncate(time.Minute))
		}
	}
}
