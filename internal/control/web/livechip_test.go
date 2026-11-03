// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

const markRun = "r-aaaaaaaa-0000000000019-markxx"

// liveGapLine is the launcher's gap line confirming serial.
func liveGapLine(run string, seq int, ts time.Time, kind, value string, serial int) string {
	return line(run, "probe", seq, ts, "gap", fmt.Sprintf(
		`"what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"%s","value":"%s","rule":"live.block[%s:%s]","by":"uid:1000 pid:9 cli","serial":%d,"at":"2026-10-25T12:01:10Z"}`,
		kind, value, kind, value, serial))
}

// addOverlay writes the run's live blocks, each added in order (serials from 1).
func addOverlay(t *testing.T, root, run string, blocks ...[2]string) {
	t.Helper()
	_, err := liveblock.Update(context.Background(), filepath.Join(root, run), run, func(o *liveblock.Overlay) (bool, error) {
		for _, b := range blocks {
			if _, _, err := o.Add(liveblock.Kind(b[0]), b[1], "uid:1000 pid:9 cli", time.Date(2026, 10, 25, 12, 1, 9, 0, time.UTC)); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// blockPanel is the r-run-live region of a run page.
func blockPanel(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `data-live="r-run-live"`)
	j := strings.Index(body, `data-live="r-run-hl"`)
	if i < 0 || j < i {
		t.Fatalf("no r-run-live region before r-run-hl")
	}
	return body[i:j]
}

// TestRunLiveWatched: on a tego watch run the panel offers a mark, says why, and every block reads "Recorded, not
// enforced", even with the launcher's line confirming it. Nothing says a block is refused.
func TestRunLiveWatched(t *testing.T) {
	root := fixture(t)
	t0 := time.Date(2026, 10, 25, 12, 1, 0, 0, time.UTC)
	if err := os.MkdirAll(filepath.Join(root, markRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, markRun, "events.jsonl"), []byte(
		line(markRun, "probe", 0, t0, "run_start", `"tier":"observe","command":["codex"],"fs_reads":{"reads":"direct","why":"records-only"},"reads_notified":{"notified":false,"why":"records-only"}`)+
			liveGapLine(markRun, 1, t0.Add(time.Second), "path", "/p/data", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	markLive(t, root, markRun)
	addOverlay(t, root, markRun, [2]string{"path", "/p/data"})
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/runs/"+markRun)
	live := blockPanel(t, body)
	mustContain(t, "the watched run's panel", live, "Recorded, not enforced", "Mark (recorded only)", "marked by", "only watched", "/static/live.css")
	mustContain(t, "the watched run's head", body, ">Mark (recorded only)</a>")
	for _, bad := range []string{"Refused by tego until the run ends", "In force", ">Block now<", "blocked by"} {
		if strings.Contains(body, bad) {
			t.Errorf("the watched run's page says %q", bad)
		}
	}
	rules := get(t, s, c, "/rules?run="+markRun)
	mustContain(t, "the watched run's Rules page", rules, "Recorded, not enforced: this run is only watched", "Marked now (recorded, not refused)",
		"Marked live now", "Marks you added while the agent is watched. They record what matches and refuse nothing.", "A mark refuses nothing",
		`class="panel rules-live is-calm"`)
	for _, bad := range []string{"Refused by tego until the run ends", "Blocked now:", "Blocked live now", "A live block refuses more"} {
		if strings.Contains(rules, bad) {
			t.Errorf("the watched run's Rules page claims a refusal: %q", bad)
		}
	}
}

// TestRunPageUnreadableLiveBlocks: a live-blocks file the run page's Block now panel cannot read is said in plain
// words, as the Rules page says it (rulesview.LiveErrWords): the file and what is wrong with it, never liveblock's
// error with its package prefixes, a JSON decoder's words or the run's folder.
func TestRunPageUnreadableLiveBlocks(t *testing.T) {
	root := fixture(t)
	overlay := filepath.Join(root, harmRun, liveblock.FileName)
	s := newServer(t, root)
	c := login(t, s)
	check := func(name, want string) {
		t.Helper()
		live := blockPanel(t, get(t, s, c, "/runs/"+harmRun))
		mustContain(t, name, live, "The run's live blocks could not be read: "+want+".")
		for _, raw := range []string{"liveblock:", "invalid character", "overlay file", filepath.Join(root, harmRun)} {
			if strings.Contains(live, raw) {
				t.Errorf("%s: the panel says %q", name, raw)
			}
		}
	}
	if err := os.WriteFile(overlay, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("a damaged file", "live-block.json is damaged, or a newer Tego wrote it")
	if err := os.Chmod(overlay, 0o666); err != nil {
		t.Fatal(err)
	}
	check("a file others may write", "live-block.json is writable by its group or others, so it is not trusted")
	if os.Geteuid() != 0 { // root reads a file whatever its mode says
		if err := os.Chmod(overlay, 0o200); err != nil {
			t.Fatal(err)
		}
		check("a file this user may not read", "this user may not read live-block.json")
	}
}

// TestRunLiveEnforcing: on an enforcing run a block waits until the launcher's line confirms its serial, then reads "In
// force since line #N"; the change arrives as a fresh r-run-live region (what live.js swaps in over /events), and the
// Rules page says the same states.
func TestRunLiveEnforcing(t *testing.T) {
	root := fixture(t)
	t0 := time.Date(2026, 10, 25, 12, 1, 10, 0, time.UTC)
	addOverlay(t, root, harmRun, [2]string{"exec", "curl"}, [2]string{"path", "/p/secret"})
	appendLine(t, root, harmRun, liveGapLine(harmRun, 7, t0, "exec", "curl", 1))
	s := newServer(t, root)
	c := login(t, s)
	page := "/runs/" + harmRun
	body := get(t, s, c, page)
	live := blockPanel(t, body)
	mustContain(t, "the enforcing run's panel", live, "In force since line #7", "Waiting for the run…", ">Block now<", `name="csrf" value="`+s.csrf+`"`)
	if strings.Contains(body, "Recorded, not enforced") || strings.Contains(body, "Mark (recorded only)") {
		t.Error("the enforcing run's page reads as watched")
	}
	rules := get(t, s, c, "/rules?run="+harmRun)
	mustContain(t, "the enforcing run's Rules page", rules, "Blocked now: cannot run curl", "In force: tego refuses it until the run ends",
		"Blocking: cannot open or change /p/secret", "Waiting for the run to put it in force",
		"Blocked live now", "A live block refuses more than the rules file, never less", `class="panel rules-live"`)

	// The launcher confirms serial 2: the region answer carries the new state. The run's reads are not seen (no
	// fs_reads held), so the path block refuses changes only.
	have := regionsIn(body)
	appendLine(t, root, harmRun, liveGapLine(harmRun, 8, t0.Add(400*time.Millisecond), "path", "/p/secret", 2))
	w := doRegions(s, page, "127.0.0.1:8484", c, headerOf(have))
	frag := regexp.MustCompile(`(?s)<template data-live="r-run-live" data-h="[0-9a-f]{16}">(.*?)</template>`).FindStringSubmatch(w.Body.String())
	if frag == nil {
		t.Fatalf("no fresh r-run-live region after the confirming line: %s", w.Body.String())
	}
	mustContain(t, "the fresh r-run-live region", frag[1], "In force since line #7", "Changes refused since line #8", "reads are not seen", `name="csrf" value="`+s.csrf+`"`)
	if strings.Contains(frag[1], "Waiting for the run") {
		t.Error("the confirmed block still waits")
	}
	rules = get(t, s, c, "/rules?run="+harmRun)
	mustContain(t, "the Rules page after the confirming line", rules, "Blocked now: cannot change /p/secret (reads still go through)", "Refuses changes now; reads are not seen in this run")
}

// TestBlockLineShortens: a block's value reads as the rest of the run page writes paths, "~/" for the run's home and
// "./" for its working directory (the deeper root that holds it), with Full the value as written; a program name, a
// destination and a path outside both roots stay as written, and a mark says marked.
func TestBlockLineShortens(t *testing.T) {
	r := &ledgerview.Run{User: "alice", UID: 1000, Cwd: "/s/stage/with/repo"}
	const home = "/s/stage/with/home"
	at := time.Date(2026, 10, 27, 21, 50, 53, 0, time.Local)
	for _, c := range []struct {
		kind        liveblock.Kind
		value, want string
	}{
		{liveblock.KindRead, home + "/.config/telemetry", "~/.config/telemetry"},
		{liveblock.KindPath, home + "/.aws/", "~/.aws/"},
		{liveblock.KindWrite, "/s/stage/with/repo/vault", "./vault"},
		{liveblock.KindRead, "/s/stage/with/homes/x", "/s/stage/with/homes/x"}, // only home itself, never a sibling that starts the same
		{liveblock.KindRead, "/etc/shadow", "/etc/shadow"},
		{liveblock.KindExec, "curl", "curl"},
		{liveblock.KindNet, "127.0.0.1:8802", "127.0.0.1:8802"},
	} {
		b := liveblock.Entry{Kind: c.kind, Value: c.value, By: "uid:1000 pid:7 dashboard", At: at}
		got := blockLine(b, r, home)
		if got.Value != c.want || got.Full != c.value || got.Kind != kindWord(c.kind) || got.Rest != ": blocked by alice, from the dashboard at 21:50:53" {
			t.Errorf("%s %s: %+v, want the value %q", c.kind, c.value, got, c.want)
		}
		if m := markLine(b, r, home); m.Value != c.want || m.Rest != ": marked by alice, from the dashboard at 21:50:53" {
			t.Errorf("%s %s marked: %+v", c.kind, c.value, m)
		}
	}
	if got := blockLine(liveblock.Entry{Kind: liveblock.KindRead, Value: home + "/x"}, nil, ""); got.Value != home+"/x" {
		t.Errorf("with no run and no home the value is shortened: %q", got.Value)
	}
}

// TestRunLiveBlockHome: the Block now panel writes a block under the run's home (ledgerview.RunHome, the demo's
// stage/with/home) as ~/…, as Highlights writes the token beside it, with the full path in the value's title; the
// Remove form and the row's key keep the full value.
func TestRunLiveBlockHome(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000025-homexx"
	const home = "/s/stage/with/home"
	root := fixture(t)
	t0 := time.Date(2026, 10, 25, 12, 1, 0, 0, time.UTC)
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(
		line(run, "supply-chain", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/s/stage/with/repo"`)+
			line(run, "supply-chain", 1, t0.Add(time.Second), "refused", `"rule":"fs.deny_read[`+home+`/.config/telemetry/]","reason":"read-denied","op":"open","target":"`+home+`/.config/telemetry/token"`)+
			liveGapLine(run, 2, t0.Add(2*time.Second), "read", home+"/.config/telemetry", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	markLive(t, root, run)
	addOverlay(t, root, run, [2]string{"read", home + "/.config/telemetry"}, [2]string{"exec", "curl"})
	s := newServer(t, root)
	c := login(t, s)
	live := blockPanel(t, get(t, s, c, "/runs/"+run))
	mustContain(t, "the run's Block now panel", live,
		`Reads of <span title="`+home+`/.config/telemetry">~/.config/telemetry</span>: blocked by`,
		`Program curl: blocked by`, // nothing to shorten: no inner title
		`data-k="read:`+home+`/.config/telemetry"`, `name="value" value="`+home+`/.config/telemetry"`, "In force since line #2")
	if strings.Contains(live, "Reads of "+home) || strings.Contains(live, ">"+home+"/.config/telemetry<") {
		t.Errorf("the panel writes the run's home in full: %s", live)
	}
}
