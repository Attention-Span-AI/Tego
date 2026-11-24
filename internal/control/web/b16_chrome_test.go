// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// b16Shoot opens page at each width and theme the dashboard owes (390 and 1280 px, light and dark), checks the text
// the person reads there contains every want and none of the nots, the page scrolls nowhere sideways and, at 390 px,
// has no control under 24 by 24 px. TEGO_CHROME_SHOTS saves each window.
func b16Shoot(t *testing.T, c *cdp, addr, name, page, at string, wants, nots []string) {
	t.Helper()
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%s/%d/%s", name, w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + page + "?t=tok123"})
				tb.until(t, "the page", `document.readyState==='complete'&&document.fonts.status==='loaded'&&!!document.querySelector('main')`)
				tb.eval(t, `document.querySelectorAll('details').forEach(function (d) { d.open = true; }), ""`)
				body := strings.Join(strings.Fields(strings.ReplaceAll(unquote(tb.eval(t, `document.querySelector('main').innerText`)), "\n", " ")), " ")
				for _, want := range wants {
					if !strings.Contains(body, want) {
						t.Errorf("the page lacks %q", want)
					}
				}
				for _, not := range nots {
					if strings.Contains(body, not) {
						t.Errorf("the page still says %q", not)
					}
				}
				if tb.eval(t, `JSON.parse(`+builderMeasure+`).contrastFailures.length===0`) != "true" {
					t.Error("rendered contrast failed")
				}
				pageChecks(t, tb, name, w, fmt.Sprintf("b16-%s-%d-%s", name, w, theme), at)
			})
		}
	}
}

// unquote is a CDP string result as the text it holds.
func unquote(s string) string {
	var out string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return s
	}
	return out
}

// TestB16PauseWordsInChrome (C159): a pause the run has not confirmed, a pause held behind the agent's own waiting
// request, and a run that is paused, each say what is frozen, what still runs and the one way back.
func TestB16PauseWordsInChrome(t *testing.T) {
	page := "/runs/" + harmRun
	c := placeChrome(t)
	// The agent waits on a request, and a pause failed behind it.
	root := pauseFixture(t)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	appendLines(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 1, 7, 0, time.UTC), "gap",
		`"what":"enforce","why":"pause-failed","live_control":{"op":"pause","by":"uid:1000 pid:9 cli","serial":1,"at":"2026-10-25T12:00:00Z"}`))
	b16Shoot(t, c, addr, "pause-behind-request", page, ".banner-warn",
		[]string{"The pause did not take yet.", "The agent is still running", "Answer the request and Tego freezes the agent then", "Cancel pause drops your pause; the request the agent waits on stays for you to answer"},
		[]string{"Withdraw pause", "takes the request back"})

	// A pause the run has not confirmed, then one it has.
	root = pauseFixture(t)
	_, addr, _ = liveServer(t, root, 10*time.Second, 30*time.Second)
	answerAsk7(t, root, 7)
	if _, err := liveblock.Update(context.Background(), filepath.Join(root, harmRun), harmRun, func(o *liveblock.Overlay) (bool, error) {
		_, ok := o.Pause(liveblock.By("dashboard"), time.Now())
		return ok, nil
	}); err != nil {
		t.Fatal(err)
	}
	b16Shoot(t, c, addr, "pause-asked", page, ".banner-paused",
		[]string{"waiting for the run to confirm it", "The agent is still running and has not been frozen", "Cancel pause drops your pause"},
		[]string{"Withdraw pause", "withdraws the request"})
	appendLines(t, root, harmRun, pauseLine(8, time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC), "run-paused", "pause"))
	b16Shoot(t, c, addr, "paused", page, ".banner-paused",
		[]string{"The agent is frozen where it stood", "Tego itself keeps running", "Resume lets it carry on"}, nil)
}

// TestB16TimedBlockInChrome (C215): a block whose limit passed on the page's clock only is still in force; once the
// launcher records the end it reads as ended, with the absolute time and its zone beside how far away it is.
func TestB16TimedBlockInChrome(t *testing.T) {
	root := fixture(t)
	dir := filepath.Join(root, harmRun)
	t0 := time.Now().Truncate(time.Second)
	until := t0.Add(3 * time.Hour)
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
	var skew atomic.Int64 // what the page's clock is stepped forward by
	_, addr, _ := liveServerConfig(t, Config{Ledger: root, Machine: config.Builtin(), Now: func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }}, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	abs := chipUntil(until, t0)
	page := "/runs/" + harmRun
	b16Shoot(t, c, addr, "block-ahead", page, "#block", []string{"In force since line #7", "until " + abs + " (in 3 hours)"}, nil)
	skew.Store(int64(5 * time.Hour)) // the wall clock stepped forward past the limit: the launcher has recorded nothing
	b16Shoot(t, c, addr, "block-stepped", page, "#block",
		[]string{"has passed on this clock, but the run keeps its own time"}, []string{"Ended at"})
	appendLine(t, root, harmRun, limitGapLine(8, until.Add(time.Second), "live-block-expired", "exec", "/usr/bin/curl", lb.Serial, until))
	b16Shoot(t, c, addr, "block-ended", page, "#block", []string{"Ended at " + abs, "it refuses nothing now"}, []string{"In force since line #7"})
}

// TestB16TimeLimitZoneInChrome (C216): the browser fills its own zone into a time limit form, at the date typed.
// The window is told its zone (Emulation.setTimezoneOverride), so a test run anywhere reads the same offsets.
func TestB16TimeLimitZoneInChrome(t *testing.T) {
	s, c0, _ := liveFenceServer(t)
	_ = c0
	_, addr, _ := liveServer(t, s.cfg.Ledger, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, w := range []int{390, 1280} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("zone/%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				defer c.call(t, "", "Target.closeTarget", map[string]any{"targetId": tb.target})
				c.call(t, tb.session, "Emulation.setTimezoneOverride", map[string]any{"timezoneId": "America/New_York"})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + adjRun + "?t=tok123"})
				tb.until(t, "the page", `document.readyState==='complete'&&!!document.querySelector('select[name=for]')`)
				// What the form sends: summer time in July (240), winter time in January (300), today's when nothing is typed.
				for _, tc := range []struct{ until, want string }{{"2027-07-01T09:00", "240"}, {"2027-01-15T09:00", "300"}} {
					got := tb.eval(t, `(function () { var f = document.querySelector('select[name=for]').form; f.querySelector('[name=until]').value = `+fmt.Sprintf("%q", tc.until)+`; return new FormData(f).get('tz'); })()`)
					if got != `"`+tc.want+`"` {
						t.Errorf("a limit typed as %s sends tz %s, want %q", tc.until, got, tc.want)
					}
				}
				if got := tb.eval(t, `(function () { var f = document.querySelector('select[name=for]').form; f.querySelector('[name=until]').value = ""; return new FormData(f).get('tz') !== ""; })()`); got != "true" {
					t.Errorf("a form with no time typed sends no zone: %s", got)
				}
				pageChecks(t, tb, "zone", w, fmt.Sprintf("b16-zone-%d-%s", w, theme), "#block")
			})
		}
	}
}

// TestB16LeastPrivilegeSoFarInChrome (C118): a running run's Least privilege says what it covers.
func TestB16LeastPrivilegeSoFarInChrome(t *testing.T) {
	root, _ := runningDriftFixture(t)
	_, addr, _ := liveServerConfig(t, Config{Ledger: root, Machine: &config.Machine{Home: t.TempDir()}}, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	last := time.Date(2026, 10, 25, 12, 0, 1, 0, time.UTC).Local().Format("15:04:05")
	b16Shoot(t, c, addr, "least-privilege", "/runs/"+cleanRun+"/least-privilege", ".lp-sofar",
		[]string{"This run is still running, so this covers only what it did up to " + last, "The run has not ended: this covers only what it did up to " + last}, nil)
}

// TestB16HighlightsNeverAllowInChrome (C131): a secret in Highlights has its route to Never allow.
func TestB16HighlightsNeverAllowInChrome(t *testing.T) {
	root, _, proj := detailFixture(t)
	secret := filepath.Join(proj, "a", "b", ".env")
	evs, err := os.ReadFile(filepath.Join(root, detailRun, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, detailRun, "events.jsonl"), []byte(strings.Replace(string(evs), filepath.Join(proj, "a", "b", "secret.txt"), secret, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, addr, _ := liveServerConfig(t, Config{Ledger: root, Machine: config.Builtin(), Rules: &rules.Service{Ledger: root, Now: time.Now, Check: func(string, string, []byte) error { return nil }}}, 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	b16Shoot(t, c, addr, "highlights", "/runs/"+detailRun, ".hl-act", []string{"Never allow"}, nil)
}
