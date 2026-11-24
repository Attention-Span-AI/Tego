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

	"github.com/attention-span-ai/tego/internal/rulefile"
	"golang.org/x/net/html"
)

// The Change rules journey: over one real run at tier landlock, a person opens Change
// rules on the dashboard, removes /bin/ls from the programs, sees the preview say Narrows with "Also apply now" ticked
// for the running run, and saves. The rules file loses the entry, the running run gets a live block, and the agent's
// next /bin/ls is refused while the run goes on, while /bin/sleep, which the new rules still allow, keeps running. Undo
// then gives the file its exact old text back.
//
// On a host whose core utilities are one multi-call program under many names (Ubuntu 25.10 and 26.04: uutils, about
// 115 hard links of one file), /bin/ls and /bin/sleep are one file. The block "Also apply now" places matches that file
// under the removed name only (liveblock.MatchLink), so it refuses what the next run's contract refuses and no more:
// before, it matched the whole file and refused /bin/sleep too, and the agent's wait loop spun on refused sleeps. On a
// host with GNU coreutils they are two files and the check holds trivially.

const rulesAgent = `#!/bin/sh
/bin/ls > out/ls1.txt; echo $? > out/rc1
until [ -e out/go ]; do /bin/sleep 0.1; done
/bin/ls > out/ls2.txt 2> out/err2.txt; echo $? > out/rc2
/bin/sleep 0 2> out/err3.txt; echo $? > out/rc3
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

	// Submit the actual reviewed form: even a narrowing carries its retained
	// review acknowledgement. Reconstructing only the edit asks for review again.
	save := rulesSaveForm(t, preview)
	for key, want := range map[string]string{"c": ref[1], "base": base[1], "op": "remove", "key": "exec.allow", "v": "/bin/ls", "now": id} {
		if save.Get(key) != want {
			t.Fatalf("rendered Save %s = %q, want %q", key, save.Get(key), want)
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{48}\.[0-9a-f]{64}$`).MatchString(save.Get("ack")) || save.Get("csrf") == "" {
		t.Fatal("the narrowing Save form lacks its retained-review or CSRF acknowledgement")
	}
	b.readCSRF(preview)
	code, saved := b.post("/rules/change", save)
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
	// The new rules still allow /bin/sleep, so the block placed now must not refuse it, even where it is the same
	// program file as /bin/ls.
	until(t, "the agent's sleep after the change", 20*time.Second, func() bool { return out("rc3") != "" })
	if out("rc3") != "0" {
		t.Errorf("/bin/sleep, which the new rules allow, exited %q after the change applied now (%s)", out("rc3"), out("err3.txt"))
	}
	// Waited for, not read once: the supervisor answers a refused exec before the pipeline writes its line
	// ("what a reader may rely on"), so the line can land after the agent saw the refusal and
	// wrote rc2. In a gate run under load one read made as soon as rc2 appeared found no refused line, and the run's
	// ledger held it when the test ended (the second ls, refused 40 ms after the block landed).
	until(t, "an exec line refused by the live block", 20*time.Second, func() bool {
		for _, l := range kindsOf(ledgerOf(t, w.ledger, id), "exec") {
			if l.Verdict == "refused" && strings.HasPrefix(l.Rule, "live.block[exec:") {
				return true
			}
		}
		return false
	})
	for _, l := range kindsOf(ledgerOf(t, w.ledger, id), "exec") {
		if l.Verdict == "refused" && strings.Contains(l.Raw, `"path":"/bin/sleep"`) {
			t.Errorf("/bin/sleep was refused after the change applied now: %s", l.Raw)
			break
		}
	}

	// The persisted change and its live application must both be recorded.
	history, err := rulefile.History(w.ledger, contract)
	written, readErr := os.ReadFile(contract)
	if err != nil || readErr != nil || len(history) != 1 {
		t.Fatalf("saved history: %+v, err=%v read=%v", history, err, readErr)
	}
	changeEntry := history[0]
	if changeEntry.Op != rulefile.OpChange || changeEntry.Via != "dashboard" || changeEntry.Direction != "narrows" ||
		changeEntry.OldSHA256 != rulefile.Sum([]byte(rulesContract)) || changeEntry.NewSHA256 != rulefile.Sum(written) ||
		len(changeEntry.Live) != 1 || changeEntry.Live[0].Run != id || changeEntry.Live[0].Block != "exec:/bin/ls" || !changeEntry.Live[0].Placed() {
		t.Fatalf("the saved change or its live outcome was not recorded: %+v", changeEntry)
	}
	// Consumed review credentials cannot write a second change.
	code, replay := b.post("/rules/change", save)
	if code != 409 || !strings.Contains(replay, "review it again") {
		t.Fatalf("replayed Save: %d %s", code, replay)
	}
	if current, err := os.ReadFile(contract); err != nil || string(current) != string(written) {
		t.Fatal("replayed Save changed the contract")
	}

	// A fresh run must enforce the saved contract without the first run's live
	// block. Keep the still-allowed sleep as a control on multi-call coreutils.
	nextCmd := exec.Command(w.tego, "run", contract, "--", "/bin/sh", "-c", `/bin/ls > out/next-ls.txt 2> out/next-ls.err; echo $? > out/next-ls-rc
/bin/sleep 0; echo $? > out/next-sleep-rc`)
	nextCmd.Dir, nextCmd.Env = w.proj, w.env
	next := start(t, nextCmd)
	select {
	case <-next.done:
		if next.err != nil {
			t.Fatalf("next run: %v %s", next.err, next.out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("next run did not finish")
	}
	if rc := out("next-ls-rc"); rc == "" || rc == "0" || out("next-sleep-rc") != "0" {
		t.Fatalf("saved rules not in force on next run: ls=%q sleep=%q: %s", rc, out("next-sleep-rc"), out("next-ls.err"))
	}
	entries, err := os.ReadDir(w.ledger)
	if err != nil {
		t.Fatal(err)
	}
	var nextID string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "r-") && entry.Name() != id {
			if nextID != "" {
				t.Fatal("unexpected extra run")
			}
			nextID = entry.Name()
		}
	}
	refused, slept := false, false
	for _, line := range kindsOf(ledgerOf(t, w.ledger, nextID), "exec") {
		if line.Payload["path"] == "/bin/ls" && line.Verdict == "refused" && !strings.HasPrefix(line.Rule, "live.block[") {
			refused = true
		}
		if line.Payload["path"] == "/bin/sleep" && line.Verdict == "allow" {
			slept = true
		}
	}
	if nextID == "" || !refused || !slept {
		t.Fatalf("next run lacks persisted-rule refusal and allowed sleep: %s", rawOf(ledgerOf(t, w.ledger, nextID)))
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

// rulesSaveForm follows native form submission for the structured review, including
// hidden review credentials and checked Apply now boxes, without inventing fields.
func rulesSaveForm(t *testing.T, page string) url.Values {
	t.Helper()
	root, err := html.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	attribute := func(n *html.Node, name string) (string, bool) {
		for _, a := range n.Attr {
			if a.Key == name {
				return a.Val, true
			}
		}
		return "", false
	}
	var forms []*html.Node
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			action, _ := attribute(n, "action")
			if action == "/rules/change" {
				forms = append(forms, n)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(root)
	if len(forms) != 1 {
		t.Fatalf("review has %d Save forms, want one", len(forms))
	}
	values := url.Values{}
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name, _ := attribute(n, "name")
			kind, _ := attribute(n, "type")
			_, disabled := attribute(n, "disabled")
			_, checked := attribute(n, "checked")
			if name != "" && !disabled && (kind != "checkbox" || checked) {
				value, _ := attribute(n, "value")
				values.Add(name, value)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(forms[0])
	return values
}
