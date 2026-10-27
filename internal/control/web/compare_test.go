// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	watchRun = "r-aaaaaaaa-0000000000011-watchx"
	guardRun = "r-aaaaaaaa-0000000000012-guardx"
)

// compareFixture is one run that only observed and one that enforced, each going for the SSH key and an attacker's
// address.
func compareFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	write := func(run string, ls ...string) {
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(watchRun,
		line(watchRun, "watch", 0, t0, "run_start", `"tier":"observe","cwd":"/d/without/proj","launcher_user":"alice"`),
		line(watchRun, "watch", 1, t0.Add(time.Second), "fs", `"verdict":"observed","rule":"unmatched","op":"open","path":"/d/without/home/.ssh/id_rsa"`),
		line(watchRun, "watch", 2, t0.Add(2*time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(watchRun, "watch", 3, t0.Add(3*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	write(guardRun,
		line(guardRun, "guard", 0, t0.Add(time.Minute), "run_start", `"tier":"landlock","cwd":"/d/with/proj","launcher_user":"alice","contract_hash":"abcdef0123456789abcdef"`),
		// Each refused action is followed by the kind=refused line that mirrors it, as the supervisor writes them.
		line(guardRun, "guard", 1, t0.Add(time.Minute+time.Second), "fs", `"verdict":"refused","rule":"fs.deny_read[/d/with/home/.ssh/]","reason":"read-denied","op":"open","path":"/d/with/home/.ssh/id_rsa"`),
		line(guardRun, "guard", 2, t0.Add(time.Minute+time.Second), "refused", `"rule":"fs.deny_read[/d/with/home/.ssh/]","reason":"read-denied","op":"open","target":"/d/with/home/.ssh/id_rsa"`),
		line(guardRun, "guard", 3, t0.Add(time.Minute+2*time.Second), "net", `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(guardRun, "guard", 4, t0.Add(time.Minute+2*time.Second), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:8801"`),
		line(guardRun, "guard", 5, t0.Add(time.Minute+3*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	return root
}

func TestComparePage(t *testing.T) {
	s := newServer(t, compareFixture(t))
	c := login(t, s)
	get := func(path string) (int, string) {
		w := do(s, "GET", path, "127.0.0.1:8484", c)
		return w.Code, w.Body.String()
	}

	code, body := get("/compare?a=" + watchRun + "&b=" + guardRun)
	if code != http.StatusOK {
		t.Fatalf("compare: %d %s", code, body)
	}
	for _, want := range []string{
		"Run A (watch, watched) read 1 secret file and made 1 off-list connection (127.0.0.1:8801); 1 secret left (id_rsa sent to 127.0.0.1:8801).",
		"Run B (guard, enforced by Tego) read no secret file and made no off-list connection; Tego refused 2 attempts (1 secret read and 1 send to 127.0.0.1:8801).",
		// The run head's count is the verdict's too.
		"2 against secrets",
		"Watched only", "Enforced · Basic", "abcdef012345", "alice",
		// The key reads as ~/.ssh/id_rsa: both runs' homes (with/home, without/home) merge into one.
		`title="…/home/.ssh/id_rsa"`, `<span class="sp-d">~/<wbr>.ssh/</span><wbr><b class="sp-b">id_rsa</b>`,
		`class="b b-bad"`, "Got through", `class="b b-refused"`, "Stopped", "Not verified",
		"A · watch · watched", "B · guard · enforced by Tego", "cmp-danger",
		`<option value="` + watchRun + `" selected>`, `<option value="` + guardRun + `" selected>`,
		`href="/runs/` + guardRun + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("compare page lacks %q", want)
		}
	}
	// The scripts every page loads are static/theme.js and static/live.js (script-src 'self'); nothing inline.
	if inline := strings.NewReplacer(`<script src="/static/theme.js"></script>`, "", `<script src="/static/live.js" defer></script>`, "").Replace(body); strings.Contains(inline, "<script") || strings.Contains(inline, " style=") {
		t.Error("the compare page carries an inline script or an inline style")
	}

	// One run given: the page picks the other kind and compares, the watched run on the left.
	if code, body = get("/compare?a=" + guardRun); code != http.StatusOK || !strings.Contains(body, "Run A (watch, watched)") ||
		!strings.Contains(body, "Run B (guard, enforced by Tego)") || !strings.Contains(body, `<option value="`+watchRun+`" selected>`) {
		t.Errorf("compare with one run: %d, picks the observed run: %v", code, strings.Contains(body, watchRun))
	}
	// Nothing given: the chooser starts on the newest observed run against the newest enforced one, with no table.
	if code, body = get("/compare"); code != http.StatusOK || strings.Contains(body, "Sensitive actions") ||
		!strings.Contains(body, `<option value="`+guardRun+`" selected>`) {
		t.Errorf("bare compare: %d", code)
	}
	if _, body = get("/compare?a=" + watchRun + "&b=" + watchRun); !strings.Contains(body, "Choose two different runs") {
		t.Error("the same run twice is not refused")
	}
	if _, body = get("/compare?a=" + watchRun + "&b=r-nope"); !strings.Contains(body, "No run r-nope is in this ledger root.") {
		t.Error("an unknown run is not named")
	}
	// The way in: the Runs page chooser and the run page's Compare link.
	if _, body = get("/runs"); !strings.Contains(body, `action="/compare"`) {
		t.Error("the Runs page has no compare form")
	}
	if _, body = get("/runs/" + guardRun); !strings.Contains(body, `href="/compare?a=`+guardRun+`"`) {
		t.Error("the run page has no Compare link")
	}
}
