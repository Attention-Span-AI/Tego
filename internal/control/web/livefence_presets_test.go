// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// shortPresets are the time limits under an hour every live change's select offers, with their labels.
var shortPresets = []struct {
	value, label string
	span         time.Duration
}{
	{"2m", "2 minutes", 2 * time.Minute},
	{"4m", "4 minutes", 4 * time.Minute},
	{"15m", "15 minutes", 15 * time.Minute},
	{"30m", "30 minutes", 30 * time.Minute},
}

// fixLiveNow makes liveNow return at until the test ends.
func fixLiveNow(t *testing.T, at time.Time) {
	t.Helper()
	old := liveNow
	liveNow = func() time.Time { return at }
	t.Cleanup(func() { liveNow = old })
}

// TestUntilOfPresets: each fixed span ends exactly that long after the clock read when the request arrives, to the
// nanosecond, in UTC; the long ones are unchanged; a limit still ends 1 minute to 400 days ahead.
func TestUntilOfPresets(t *testing.T) {
	now := time.Date(2026, 10, 27, 20, 31, 51, 123456789, time.FixedZone("CET", 3600))
	want := map[string]time.Duration{"1h": time.Hour, "1d": 24 * time.Hour, "3d": 72 * time.Hour, "1w": 7 * 24 * time.Hour}
	for _, p := range shortPresets {
		want[p.value] = p.span
	}
	if len(forSpans) != len(want) {
		t.Errorf("forSpans has %d spans, want %d: %v", len(forSpans), len(want), forSpans)
	}
	for choice, d := range want {
		end, perm, err := untilOf(choice, "", "", "", now)
		if err != nil || perm || !end.Equal(now.Add(d)) || end.Location() != time.UTC {
			t.Errorf("untilOf(%q) = %v, %v, %v; want %v in UTC", choice, end, perm, err, now.Add(d).UTC())
		}
	}
	for _, tc := range []struct{ choice, until string }{
		{"1m", ""},                       // not a preset
		{"until", "2026-10-27T20:32:30"}, // 39 s ahead: under the 1 minute floor
		{"until", "2027-12-31T20:31"},    // past 400 days
	} {
		if _, _, err := untilOf(tc.choice, tc.until, "", "-60", now); err == nil {
			t.Errorf("untilOf(%q, %q) took it", tc.choice, tc.until)
		}
	}
	if end, _, err := untilOf("until", "2026-10-27T20:33", "", "-60", now); err != nil || end.Sub(now) != 69*time.Second-123456789 {
		t.Errorf("until 20:33 at 20:31:51.123: %v, %v; want 69 s less the fraction (until… takes a whole minute)", end, err)
	}
}

// forOptions are the values of a page's time limit selects, in order.
var forOptions = regexp.MustCompile(`<option value="([a-z0-9]+)"(?: selected="selected")?>([^<]*)</option>`)

// TestShortPresetsOffered: the run page's Block now form and the Rules page's Lift… and Grant… forms offer 2, 4, 15
// and 30 minutes before the long limits, and every value a select offers is one untilOf knows.
func TestShortPresetsOffered(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	for _, page := range []string{"/runs/" + adjRun, "/rules?run=" + adjRun} {
		w := do(s, "GET", page, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", page, w.Code)
		}
		body := w.Body.String()
		sel := strings.Index(body, `<select class="select" name="for">`)
		if sel < 0 {
			t.Fatalf("%s has no time limit select", page)
		}
		opts := forOptions.FindAllStringSubmatch(body[sel:sel+strings.Index(body[sel:], "</select>")], -1)
		var values []string
		for _, o := range opts {
			values = append(values, o[1])
			if _, ok := forSpans[o[1]]; !ok && o[1] != forRun && o[1] != forTyped && o[1] != forUntil && o[1] != forPerm {
				t.Errorf("%s offers %q, which untilOf refuses", page, o[1])
			}
		}
		if got, want := strings.Join(values, " "), "2m 4m 15m 30m 1h 1d 3d 1w run for until perm"; got != want {
			t.Errorf("%s's time limits: %s\nwant %s", page, got, want)
		}
		for _, p := range shortPresets {
			mustContain(t, page, body, `<option value="`+p.value+`">`+p.label+`</option>`)
		}
		mustContain(t, page, body, `<option value="for">for…</option>`, `<label class="field lf-span">For<input class="input" type="text" name="span"`)
	}
}

// TestBlockShortPreset: Block now with a short preset blocks until exactly that long after the click, so a 2-minute
// block lasts 2 minutes and not to the next whole minute.
func TestBlockShortPreset(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	for i, p := range shortPresets {
		click := time.Now().Add(time.Duration(i) * time.Millisecond)
		fixLiveNow(t, click)
		value := "/bin/b" + p.value
		f := url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {value}, "for": {p.value}}
		b := follow(t, s, c, post(s, "/runs/"+adjRun+"/block", f, own, "", c))
		mustContain(t, p.value+" flash", b, "Blocked "+value+" on run r-…adjust.", "It lasts until ", "(in "+p.label+").")
		o, err := liveblock.Read(dir, adjRun)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, e := range o.Blocks {
			if e.Value == value {
				found = true
				if !e.Until.Equal(click.Add(p.span)) {
					t.Errorf("%s: the block ends %v, want %v (the click plus %s)", p.value, e.Until, click.Add(p.span).UTC(), p.span)
				}
			}
		}
		if !found {
			t.Errorf("%s: no block of %s in %+v", p.value, value, o.Blocks)
		}
	}
}

// TestLiftShortPreset: Lift… or Grant… with a short preset previews an end exactly that long after the click, names
// it in the terminal twin, and the confirm keeps that end (the acknowledgement binds it); a 2-minute preview confirmed
// more than a minute later is refused, since its limit is then under the 1 minute floor.
func TestLiftShortPreset(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	target := "/runs/" + adjRun + "/lift"
	click := time.Now()
	fixLiveNow(t, click)
	form, body := previewForm(t, s, c, target+"?kind=read&value=/srv/exports&for=4m")
	mustContain(t, "the 4m preview", body, "This run will be able to read /srv/exports now, until ", "(in 4 minutes).",
		"tego grant "+adjRun+" read /srv/exports --for 4m")
	end := click.Add(4 * time.Minute).UTC()
	if got := form.Get("until"); got != end.Format(time.RFC3339Nano) {
		t.Fatalf("the preview's until %q, want %q", got, end.Format(time.RFC3339Nano))
	}
	fixLiveNow(t, click.Add(5*time.Second))
	form.Set("understand", "yes")
	b := follow(t, s, c, post(s, target, form, own, "", c))
	mustContain(t, "the flash", b, "Asked: read /srv/exports until ")
	ch := overlayChanges(t, dir)
	if len(ch) != 1 || ch[0].Op != liveblock.OpLift || !ch[0].Until.Equal(end) {
		t.Fatalf("overlay changes %+v: want one lift ending %v", ch, end)
	}

	fixLiveNow(t, click)
	form, _ = previewForm(t, s, c, target+"?kind=exec&value=/usr/bin/psql&for=2m")
	if got := form.Get("until"); got != click.Add(2*time.Minute).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("the 2m preview's until %q", got)
	}
	fixLiveNow(t, click.Add(61*time.Second))
	form.Set("understand", "yes")
	if b := follow(t, s, c, post(s, target, form, own, "", c)); !strings.Contains(b, "the time limit has passed or is out of bounds") {
		t.Error("a 2-minute preview confirmed 61 s later: no plain line")
	}
	if ch := overlayChanges(t, dir); len(ch) != 1 {
		t.Fatalf("overlay changes %+v: the late confirm wrote", ch)
	}
}

// TestUntilOfTyped: "for…" reads the typed span with --for's parser (liveblock.ParseDuration: 45m, 4m, 72h, 3d,
// 1d12h, 7w), ends exactly that long after now, and keeps the 1 minute to 400 days bounds; an empty, unreadable, zero
// or out-of-bounds span is refused in plain words that name the syntax.
func TestUntilOfTyped(t *testing.T) {
	now := time.Date(2026, 10, 27, 20, 31, 51, 5, time.UTC)
	for span, d := range map[string]time.Duration{"45m": 45 * time.Minute, " 4m ": 4 * time.Minute, "72h": 72 * time.Hour,
		"3d": 72 * time.Hour, "1d12h": 36 * time.Hour, "7w": 49 * 24 * time.Hour, "1m": time.Minute, "400d": 400 * 24 * time.Hour,
		"90s": 90 * time.Second} {
		end, perm, err := untilOf("for", "", span, "", now)
		if err != nil || perm || !end.Equal(now.Add(d)) {
			t.Errorf("for %q: %v, %v, %v; want %v", span, end, perm, err, now.Add(d))
		}
	}
	for span, want := range map[string]string{
		"":      "type a duration such as 45m, 4m, 72h, 3d, 1d12h or 7w",
		"soon":  `for "soon": "soon" is not a number followed by a unit (ns, us, ms, s, m, h, d or w); type a duration such as 45m`,
		"-5m":   `is not a number followed by a unit`,
		"0m":    "the duration must be above zero",
		"30s":   "a time limit ends 1 minute to 400 days from now",
		"401d":  "a time limit ends 1 minute to 400 days from now",
		"9999w": "a time limit ends 1 minute to 400 days from now",
	} {
		if _, _, err := untilOf("for", "", span, "", now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("for %q: err %v, want one containing %q", span, err, want)
		}
	}
}

// TestTypedForOnForms: Block now with a typed "for…" blocks exactly that long from the click, and says a bad one in
// plain words; the lift preview reads the same field, names it in the terminal twin, and the confirm keeps its end.
func TestTypedForOnForms(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	click := time.Now()
	fixLiveNow(t, click)
	f := url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {"/bin/typed"}, "for": {"for"}, "span": {"1d12h"}}
	b := follow(t, s, c, post(s, "/runs/"+adjRun+"/block", f, own, "", c))
	mustContain(t, "the typed block's flash", b, "Blocked /bin/typed on run r-…adjust.", "It lasts until ", "(in 2 days).")
	o, err := liveblock.Read(dir, adjRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Blocks) != 1 || !o.Blocks[0].Until.Equal(click.Add(36*time.Hour)) {
		t.Fatalf("blocks %+v: want one ending 1d12h after the click", o.Blocks)
	}
	for span, want := range map[string]string{
		"soon": "Not done: the time limit is not one: for &#34;soon&#34;: &#34;soon&#34; is not a number followed by a unit",
		"":     "Not done: the time limit is not one: type a duration such as 45m, 4m, 72h, 3d, 1d12h or 7w.",
		"20s":  "Not done: the time limit is not one: a time limit ends 1 minute to 400 days from now.",
	} {
		f := url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {"/bin/bad"}, "for": {"for"}, "span": {span}}
		if b := follow(t, s, c, post(s, "/runs/"+adjRun+"/block", f, own, "", c)); !strings.Contains(b, want) {
			t.Errorf("typed %q: the page does not say %q", span, want)
		}
	}
	if o, err := liveblock.Read(dir, adjRun); err != nil || len(o.Blocks) != 1 {
		t.Fatalf("bad typed limits wrote blocks: %+v %v", o.Blocks, err)
	}

	target := "/runs/" + adjRun + "/lift"
	form, body := previewForm(t, s, c, target+"?kind=exec&value=/usr/bin/psql&for=for&span="+url.QueryEscape("45m"))
	mustContain(t, "the typed preview", body, "This run will be able to run /usr/bin/psql now, until ", "(in 45 minutes).",
		"tego lift "+adjRun+" exec /usr/bin/psql --for 45m")
	end := click.Add(45 * time.Minute).UTC()
	if form.Get("until") != end.Format(time.RFC3339Nano) {
		t.Fatalf("the typed preview's until %q, want %v", form.Get("until"), end)
	}
	form.Set("understand", "yes")
	follow(t, s, c, post(s, target, form, own, "", c))
	var lift *liveblock.Change
	for _, ch := range overlayChanges(t, dir) {
		if ch.Op == liveblock.OpLift {
			lift = &ch
		}
	}
	if lift == nil || !lift.Until.Equal(end) {
		t.Fatalf("lift %+v: want one ending %v", lift, end)
	}
	_, body = previewForm(t, s, c, target+"?kind=exec&value=/usr/bin/psql&for=for&span=2x")
	mustContain(t, "a bad typed preview", body, "The time limit is not one: for &#34;2x&#34;")
	if strings.Contains(body, `name="ack"`) || strings.Contains(body, "--for 2x") {
		t.Error("a preview with a bad typed limit offers a confirm or a terminal command")
	}
}
