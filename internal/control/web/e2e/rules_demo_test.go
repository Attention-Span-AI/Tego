// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// The demo beat over one real, governed run: the agent reads a token under an
// fs.ask_read folder whose reads the run holds; a person denies it on the dashboard, follows the Deny page's "Make it
// permanent: Never allow", and confirms the preview with "Also apply now" ticked. The agent's next read of the token is
// refused at once by the live block, without asking; the contract now refuses the folder (deny_read, no ask_read
// left), the journal holds one dashboard change, and a fresh run of the contract is refused by fs.deny_read without
// asking anyone.

// neverScript is the agent: one read of the token (asked, then denied), then, once the test writes out/go (after the
// live block is in force), a second read, then it waits for out/end.
const neverScript = `#!/bin/sh
cat "$SECRET" > out/got1.txt 2> out/err1.txt; echo $? > out/rc1
until [ -e out/go ]; do /bin/sleep 0.05; done
cat "$SECRET" > out/got2.txt 2> out/err2.txt; echo $? > out/rc2
until [ -e out/end ]; do /bin/sleep 0.1; done
`

// neverContract asks before every read under the vault folder, and holds the run's reads, so a live path block can
// refuse a read while the run goes on (ADR 0069 D1).
const neverContract = `version: 0
name: e2e-never
command: ["/bin/sh"]
tier: landlock
fs:
  reads: held
  write: ["./out/"]
  ask_read: [%q]
exec:
  allow: ["/bin/sh", "/bin/cat", "/bin/sleep"]
net: {}
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 60s
limits:
  pids: 64
record: summary
`

// TestDemoNeverAllow is the beat in the file comment.
func TestDemoNeverAllow(t *testing.T) {
	outsideEveryRun(t)
	if os.Geteuid() == 0 {
		t.Skip("tego-control refuses to run as root (the dashboard runs as the user)")
	}
	w := newWorld(t)
	vault := filepath.Dir(w.secret) + "/"
	contract := filepath.Join(w.proj, "agent.yaml")
	write(t, contract, fmt.Sprintf(neverContract, vault), 0o600)
	write(t, filepath.Join(w.proj, "agent.sh"), strings.ReplaceAll(neverScript, "$SECRET", w.secret), 0o700)
	t.Cleanup(func() {
		if t.Failed() {
			for _, id := range runIDs(w.ledger) {
				t.Logf("run %s's ledger:\n%s", id, rawOf(ledgerOf(t, w.ledger, id)))
			}
		}
	})
	out := func(name string) string { return readTrim(filepath.Join(w.proj, "out", name)) }

	cmd := exec.Command(w.tego, "run", contract, "--", "/bin/sh", "agent.sh")
	cmd.Dir = w.proj
	cmd.Env = w.env
	run := start(t, cmd)
	var id string
	until(t, "the run's run_start line", 30*time.Second, func() bool {
		if run.over() {
			t.Fatalf("tego run ended first: %v\n%s", run.err, run.out.String())
		}
		id = runID(w.ledger)
		return id != "" && len(kindsOf(ledgerOf(t, w.ledger, id), "run_start")) == 1
	})
	b := serveDashboard(t, w)
	b.signIn()
	until(t, "the token read's ask", 30*time.Second, func() bool { return b.status().Pending == 1 })
	cards := b.cards()
	if len(cards) != 1 || cards[0].target != w.secret {
		t.Fatalf("Approvals shows %+v, want the token %s", cards, w.secret)
	}
	_, approvals := b.get("/approvals")
	b.readCSRF(approvals)

	// Deny: the answer's line (the flash line of the page the form returns to; live.js's toast in a browser) offers
	// "Make it permanent: Never allow", which opens the decided line's preview on its Act panel.
	code, page := b.post("/approvals/answer", url.Values{"run": {id}, "ask": {cards[0].id}, "decision": {"deny"}})
	never := regexp.MustCompile(`href="(/runs/` + regexp.QuoteMeta(id) + `/lines/[0-9]+\?decided=1)(?:#act)?"[^>]*>.*Make it permanent: Never allow`).FindStringSubmatch(page)
	if code != http.StatusOK || never == nil {
		t.Fatalf("Deny: %d, Never allow link %v\n%s", code, never, page)
	}
	until(t, "the denied read's result", 20*time.Second, func() bool { return out("rc1") != "" })
	if out("rc1") == "0" || out("got1.txt") != "" {
		t.Fatalf("the denied read exited %q with %q", out("rc1"), out("got1.txt"))
	}
	// The refusal line may follow the answer by a moment; the link waits for it.
	var preview string
	until(t, "the Never allow preview", 10*time.Second, func() bool {
		code, preview = b.get(never[1])
		return code == http.StatusOK && strings.Contains(preview, "Confirm: never allow")
	})
	// The sentences name the folder as the page writes paths: under the home as ~/…, under the run's folder as ./….
	// A long path breaks only between its folders (a <wbr> after each "/", a hyphenated folder kept whole), so the
	// words are read without those marks.
	said := regexp.MustCompile(`<wbr>|<span class="nb">([^<]*)</span>`).ReplaceAllString(preview, "$1")
	if !regexp.MustCompile(`Asks you before it reads [^<]*/vault/</span>.*Can never read [^<]*/vault/</strong>`).MatchString(said) {
		t.Error("the preview does not say the change as Asks you before it reads …/vault/ → Can never read …/vault/")
	}
	for _, want := range []string{
		"b b-narrows", "Also apply now",
		`name="now" value="` + id + `" checked`, "read:" + strings.TrimSuffix(vault, "/"),
	} {
		if !strings.Contains(preview, want) {
			t.Errorf("the preview lacks %q", want)
		}
	}
	form := url.Values{"a": {"block"}, "now": {id}}
	for _, f := range []string{"base", "level"} {
		m := regexp.MustCompile(`name="` + f + `" value="([^"]+)"`).FindStringSubmatch(preview)
		if m == nil {
			t.Fatalf("the preview's confirm has no %s field", f)
		}
		form.Set(f, m[1])
	}
	line := regexp.MustCompile(`<form id="act-confirm" method="post" action="(/runs/[^"#]+)#act"><input type="hidden" name="csrf"`).FindStringSubmatch(preview)
	if line == nil {
		t.Fatal("the preview has no confirm form")
	}
	shoot(t, w, b, line[1]+"?a=block")
	f := url.Values{"csrf": {b.csrf}}
	for k, v := range form {
		f[k] = v
	}
	req, err := http.NewRequest("POST", b.root+line[1], strings.NewReader(f.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.root)
	for _, ck := range b.c.Jar.Cookies(req.URL) {
		req.AddCookie(ck)
	}
	resp, err := b.bare.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	// The bound runs from the Confirm: the demo's "refused at once" includes the supervisor picking up the block.
	goAt := time.Now()
	here := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(here, "?saved=") {
		t.Fatalf("confirm: %d to %q", resp.StatusCode, here)
	}
	code, saved := b.get(here)
	// The saved panel says the block is being put in force on this run until the launcher's confirming line
	// arrives (about half a second), never "Waiting", and never "Live now" before that line.
	if code != http.StatusOK || !strings.Contains(saved, `name="undo"`) ||
		!(strings.Contains(saved, "Putting it in force on this run…") || strings.Contains(saved, "Live now on this run")) {
		t.Fatalf("confirm: %d\n%s", code, saved)
	}
	// The same address, read again as the page's live updates read it, says Live now with the confirming line
	// within about a second (the bound here is the test's 2 s).
	until(t, "the saved panel saying Live now", 10*time.Second, func() bool {
		_, again := b.get(here)
		// The green chip "Live now on this run", then the line it came in force at.
		return strings.Contains(again, `Live now on this run</span><span class="ev-live-st">in force since line #`)
	})
	if took := time.Since(goAt); took > 2*time.Second {
		t.Errorf("the saved panel said Live now %s after the Confirm, the bound is 2 s", took.Round(10*time.Millisecond))
	}

	// The live block is in force: the agent's next read is refused at once, by the block, with no new ask.
	until(t, "the live-block-added line", 20*time.Second, func() bool {
		for _, g := range kindsOf(ledgerOf(t, w.ledger, id), "gap") {
			if strings.Contains(g.Raw, "live-block-added") {
				return true
			}
		}
		return false
	})
	if took := time.Since(goAt); took > 2*time.Second {
		t.Errorf("the live block was in force %s after the Confirm, the bound is 2 s", took.Round(10*time.Millisecond))
	}
	asksBefore := len(kindsOf(ledgerOf(t, w.ledger, id), "ask"))
	write(t, filepath.Join(w.proj, "out", "go"), "", 0o644)
	until(t, "the second read's result", 10*time.Second, func() bool { return out("rc2") != "" })
	if took := time.Since(goAt); took > 2*time.Second {
		t.Errorf("the second read was refused %s after the Confirm, the bound is 2 s", took.Round(10*time.Millisecond))
	}
	if out("rc2") == "0" || out("got2.txt") != "" {
		t.Errorf("the blocked read exited %q with %q", out("rc2"), out("got2.txt"))
	}
	// The supervisor answers the read before its line reaches the ledger (the event is queued after the answer,
	// R23), so the agent's rc2 can land a moment before the refusal line: wait for the line, as the Never allow
	// link above waits for the first one.
	var lines []ledgerLine
	until(t, "a read refused by live.block[read:…]", 10*time.Second, func() bool {
		lines = ledgerOf(t, w.ledger, id)
		for _, l := range lines {
			if strings.HasPrefix(l.Rule, "live.block[read:") && (l.Verdict == "refused" || l.Kind == "refused") {
				return true
			}
		}
		return false
	})
	if n := len(kindsOf(lines, "ask")); n != asksBefore {
		t.Errorf("the blocked read asked: %d ask lines, %d before", n, asksBefore)
	}

	// The contract refuses the folder for every later run, and the journal holds the one dashboard change.
	got, _ := os.ReadFile(contract)
	if !strings.Contains(string(got), "deny_read:") || !strings.Contains(string(got), vault) || strings.Contains(string(got), "ask_read") {
		t.Errorf("the contract is\n%s", got)
	}
	js, err := rulefile.ReadJournal(w.ledger)
	var changes []rulefile.Entry
	for _, e := range js {
		if e.Op == rulefile.OpChange {
			changes = append(changes, e)
		}
	}
	if err != nil || len(changes) != 1 || changes[0].Via != "dashboard" || changes[0].Direction != "narrows" {
		t.Errorf("journal changes %+v (%v)", changes, err)
	}

	// End the run, then run the contract again: the read is refused by fs.deny_read and nobody is asked.
	write(t, filepath.Join(w.proj, "out", "end"), "", 0o644)
	select {
	case <-run.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("tego run did not end\n%s", run.out.String())
	}
	again := exec.Command(w.tego, "run", contract, "--", "/bin/sh", "-c", `cat "$0" > out/got3.txt 2> out/err3.txt; echo $? > out/rc3`, w.secret)
	again.Dir, again.Env = w.proj, w.env
	if o, err := again.CombinedOutput(); out("rc3") == "" {
		t.Fatalf("the second run: %v\n%s", err, o)
	}
	if out("rc3") == "0" || out("got3.txt") != "" {
		t.Errorf("the second run read the token: %q %q", out("rc3"), out("got3.txt"))
	}
	var second string
	for _, r := range runIDs(w.ledger) {
		if r != id {
			second = r
		}
	}
	rerun := ledgerOf(t, w.ledger, second)
	if n := len(kindsOf(rerun, "ask")); n != 0 {
		t.Errorf("the second run asked %d times", n)
	}
	var denied bool
	for _, l := range rerun {
		if strings.HasPrefix(l.Rule, "fs.deny_read[") && strings.Contains(l.Raw, w.secret) {
			denied = true
		}
	}
	if !denied {
		t.Error("the second run's read was not refused by fs.deny_read")
	}
}

// serveDashboard starts tego-control serve over the world's ledger root on a free loopback port and returns a
// browser for it.
func serveDashboard(t *testing.T, w *world) *browser {
	t.Helper()
	serve := exec.Command(w.control, "serve", "--addr", "127.0.0.1:0", "--ledger", w.ledger)
	serve.Env = w.env
	pipe, err := serve.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	srv := start(t, serve)
	first := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			if u, ok := strings.CutPrefix(sc.Text(), "Tego dashboard: "); ok {
				first <- u
				break
			}
		}
		_, _ = io.Copy(io.Discard, pipe)
	}()
	select {
	case u := <-first:
		return newBrowser(t, u)
	case <-srv.done:
		t.Fatalf("tego-control serve ended first: %v\n%s", srv.err, srv.out.String())
	case <-time.After(30 * time.Second):
		t.Fatal("tego-control serve printed no URL")
	}
	return nil
}

// runIDs is every run directory of the ledger root.
func runIDs(root string) []string {
	ents, _ := os.ReadDir(root)
	var out []string
	for _, e := range ents {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	return out
}

// shoot saves a screenshot of page at 1440 px wide into $TEGO_E2E_SHOTS when it is set, with a headless Chrome of
// its own profile under the world's directory; without the variable, or without Chrome, it does nothing.
func shoot(t *testing.T, w *world, b *browser, page string) {
	t.Helper()
	dir := os.Getenv("TEGO_E2E_SHOTS")
	chrome, err := exec.LookPath("google-chrome")
	if dir == "" || err != nil {
		return
	}
	tok := strings.SplitN(b.tokURL, "?t=", 2)
	if len(tok) != 2 {
		return
	}
	sep := "?"
	if strings.Contains(page, "?") {
		sep = "&"
	}
	profile := filepath.Join(w.base, "chrome")
	shot := filepath.Join(dir, "never-allow-preview-1440.png")
	c := exec.Command(chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir="+profile,
		"--window-size=1440,1100", "--hide-scrollbars", "--screenshot="+shot, b.root+page+sep+"t="+tok[1])
	c.Env = append(os.Environ(), "HOME="+filepath.Join(w.base, "chrome-home"))
	if o, err := c.CombinedOutput(); err != nil {
		t.Logf("screenshot: %v\n%s", err, o)
		return
	}
	t.Logf("screenshot of the preview: %s", shot)
}
