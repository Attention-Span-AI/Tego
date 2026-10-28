// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"bufio"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The Change rules journey: over one real run at tier landlock, a person opens Change
// rules on the dashboard, removes /bin/ls from the programs, sees the preview say Narrows with "Also apply now" ticked
// for the running run, and saves. The rules file loses the entry, the running run gets a live block, and the agent's
// next /bin/ls is refused while the run goes on. Undo then gives the file its exact old text back.

const rulesAgent = `#!/bin/sh
/bin/ls > out/ls1.txt; echo $? > out/rc1
until [ -e out/go ]; do /bin/sleep 0.1; done
/bin/ls > out/ls2.txt 2> out/err2.txt; echo $? > out/rc2
until [ -e out/end ]; do /bin/sleep 0.1; done
`

const rulesContract = `version: 0
name: e2e-rules
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", "/bin/ls", "/bin/sleep"]
net: {}
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`

// TestRulesChangeJourney is the journey in the file comment.
func TestRulesChangeJourney(t *testing.T) {
	outsideEveryRun(t)
	if os.Geteuid() == 0 {
		t.Skip("tego-control refuses to run as root (the dashboard runs as the user)")
	}
	w := newWorld(t)
	contract := filepath.Join(w.proj, "rules.yaml")
	write(t, contract, rulesContract, 0o600)
	write(t, filepath.Join(w.proj, "rules.sh"), rulesAgent, 0o700)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the run's ledger:\n%s", rawOf(ledgerOf(t, w.ledger, runID(w.ledger))))
		}
	})
	out := func(name string) string { return readTrim(filepath.Join(w.proj, "out", name)) }

	cmd := exec.Command(w.tego, "run", contract, "--", "/bin/sh", "rules.sh")
	cmd.Dir = w.proj
	cmd.Env = w.env
	run := start(t, cmd)
	var id string
	until(t, "the agent's first ls", 30*time.Second, func() bool {
		if run.over() {
			t.Fatalf("tego run ended first: %v\n%s", run.err, run.out.String())
		}
		id = runID(w.ledger)
		return id != "" && out("rc1") != ""
	})
	if out("rc1") != "0" {
		t.Fatalf("the first ls exited %q", out("rc1"))
	}

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
	var tokenURL string
	select {
	case tokenURL = <-first:
	case <-srv.done:
		t.Fatalf("tego-control serve ended first: %v\n%s", srv.err, srv.out.String())
	case <-time.After(30 * time.Second):
		t.Fatal("tego-control serve printed no URL")
	}
	b := newBrowser(t, tokenURL)
	b.signIn()

	// Rules in force → Change rules: the Rules page's button opens the form by the file's ref.
	_, rulesPage := b.get("/rules?run=" + url.QueryEscape(id))
	change := regexp.MustCompile(`href="(/rules/change\?c=[0-9a-f]+)"`).FindStringSubmatch(rulesPage)
	if change == nil {
		t.Fatal("the Rules page has no Change rules link")
	}
	code, form := b.get(strings.ReplaceAll(change[1], "&amp;", "&"))
	ref := regexp.MustCompile(`name="c" value="([0-9a-f]{16})"`).FindStringSubmatch(form)
	base := regexp.MustCompile(`name="base" value="([0-9a-f]{64})"`).FindStringSubmatch(form)
	if code != 200 || ref == nil || base == nil || !strings.Contains(form, `<span class="mono rc-entry" title="/bin/ls">`) {
		t.Fatalf("the Change rules form: %d, ref %v base %v", code, ref, base)
	}
	b.readCSRF(form)

	q := url.Values{"c": {ref[1]}, "base": {base[1]}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"/bin/ls"}}
	code, preview := b.get("/rules/change/preview?" + q.Encode())
	for _, want := range []string{"Narrows", "<strong>From the next run</strong>", "running runs keep theirs", `name="now" value="` + id + `" checked`, "exec:/bin/ls"} {
		if code != 200 || !strings.Contains(preview, want) {
			t.Errorf("the preview (%d) lacks %q", code, want)
		}
	}
	if got := readTrim(contract) + "\n"; got != rulesContract {
		t.Fatal("the preview wrote the rules file")
	}

	q.Set("now", id)
	code, saved := b.post("/rules/change", q)
	if code != 200 || !strings.Contains(saved, "Saved · ") || !strings.Contains(saved, `<li class="rc-out" data-state="`) {
		t.Fatalf("Save: %d\n%s", code, saved)
	}
	if strings.Contains(readTrim(contract), "/bin/ls") {
		t.Error("the rules file still allows /bin/ls")
	}
	until(t, "the live-block-added line", 20*time.Second, func() bool {
		for _, g := range kindsOf(ledgerOf(t, w.ledger, id), "gap") {
			if strings.Contains(g.Raw, "live-block-added") {
				return true
			}
		}
		return false
	})
	write(t, filepath.Join(w.proj, "out", "go"), "", 0o644)
	until(t, "the agent's second ls", 20*time.Second, func() bool { return out("rc2") != "" })
	if out("rc2") == "0" {
		t.Errorf("the second ls ran after the change applied now (%s)", out("err2.txt"))
	}
	refused := false
	for _, l := range kindsOf(ledgerOf(t, w.ledger, id), "exec") {
		refused = refused || (l.Verdict == "refused" && strings.HasPrefix(l.Rule, "live.block[exec:"))
	}
	if !refused {
		t.Error("no exec line refused by the live block")
	}

	// Undo: widens, so it is acknowledged with the Ack the Saved page offers (the old ackwiden=1 undoes nothing); the
	// rules file gets its exact old text back.
	undoID := regexp.MustCompile(`action="/rules/revert"[\s\S]*?name="id" value="([^"]+)"[\s\S]*?name="base" value="([0-9a-f]{64})"[\s\S]*?name="ack" value="([0-9a-f]{64})"`).FindStringSubmatch(saved)
	if undoID == nil {
		t.Fatal("the Saved page offers no Undo with its acknowledgement")
	}
	if _, refused := b.post("/rules/revert", url.Values{"c": {ref[1]}, "id": {undoID[1]}, "base": {undoID[2]}, "ackwiden": {"1"}}); strings.Contains(refused, "Undone") {
		t.Fatal("an Undo with the old ackwiden=1 undid the change")
	}
	code, undone := b.post("/rules/revert", url.Values{"c": {ref[1]}, "id": {undoID[1]}, "base": {undoID[2]}, "ack": {undoID[3]}})
	if code != 200 || !strings.Contains(undone, "Undone") {
		t.Fatalf("Undo: %d\n%s", code, undone)
	}
	if got, _ := os.ReadFile(contract); string(got) != rulesContract {
		t.Errorf("after Undo the rules file is\n%s\nwant\n%s", got, rulesContract)
	}
	_, form = b.get("/rules/change?c=" + ref[1])
	if n := strings.Count(form, `<li class="rc-hrow">`); n != 2 {
		t.Errorf("History lists %d entries, want the change and its undo", n)
	}

	write(t, filepath.Join(w.proj, "out", "end"), "", 0o644)
	select {
	case <-run.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("tego run did not end\n%s", run.out.String())
	}
}
