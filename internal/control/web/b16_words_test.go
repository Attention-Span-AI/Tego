// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestRefusedStandInKeepsTheReason (C117): a stand-in file the dashboard or the broker refuses is answered with the
// reason it gave, not one fixed sentence. The person needs it to pick another file.
func TestRefusedStandInKeepsTheReason(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		reason string
	}{
		{"dashboard", fmt.Errorf("%w: %q: not a regular file", runact.ErrBadAlternate, "/home/a/dir"), `"/home/a/dir": not a regular file`},
		{"broker", fmt.Errorf("%w: the supervisor names the file by %q, which a person cannot be shown", askproto.ErrBadAlternate, "/x\x01"), `a person cannot be shown`},
		{"helper", &pathcheck.RemoteError{Message: `invalid stand-in file: "/home/a/x": open /home/a/x: no such file or directory`, Causes: []error{runact.ErrBadAlternate}}, "no such file or directory"},
		{"symlink", fmt.Errorf("%w: %q: name it by a path with no symbolic link in it", runact.ErrBadAlternate, "/home/a/link"), "no symbolic link in it"},
	} {
		got := answerErr(c.err)
		if !strings.Contains(got, c.reason) {
			t.Errorf("%s: the refusal %q lacks the reason %q", c.name, got, c.reason)
		}
		if !strings.Contains(got, "still waiting") || strings.Contains(got, "ask:") || strings.Contains(got, "invalid stand-in file:") || strings.Contains(got, "..") {
			t.Errorf("%s: the refusal reads %q", c.name, got)
		}
	}
	if got := answerErr(errors.Join(runact.ErrBadAlternate)); !strings.Contains(got, "stand-in file") {
		t.Errorf("a refusal with no reason names no stand-in file: %q", got)
	}
}

// TestPauseWordsSayWhatIsPausedAndHowToCancel (C159): each state of a pause says what is frozen, what still runs and
// the one way back, with one name for the button that takes a pause back and no "request" that could be the agent's
// or the person's. The old words ("Withdraw pause takes the request back") named the button twice and the request
// twice.
func TestPauseWordsSayWhatIsPausedAndHowToCancel(t *testing.T) {
	root := pauseFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	page := func() string { return f3Text(do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()) }

	// A pause that failed behind the agent's own waiting request.
	appendLines(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 1, 7, 0, time.UTC), "gap",
		`"what":"enforce","why":"pause-failed","live_control":{"op":"pause","by":"uid:1000 pid:9 cli","serial":1,"at":"2026-10-25T12:00:00Z"}`))
	body := page()
	for _, want := range []string{"The agent is still running", "Answer the request and Tego freezes the agent then", "Cancel pause drops your pause; the request the agent waits on stays for you to answer"} {
		if !strings.Contains(body, want) {
			t.Errorf("a pause held behind a waiting request lacks %q", want)
		}
	}
	appendLines(t, root, harmRun, pauseLine(8, time.Date(2026, 10, 25, 12, 1, 8, 0, time.UTC), "run-resumed", "resume"))
	answerAsk7(t, root, 9)

	// A pause that failed with nothing waiting.
	appendLines(t, root, harmRun, pauseLine(10, time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC), "pause-failed", "pause"))
	body = page()
	for _, want := range []string{"The agent is still running", "Cancel pause makes Tego stop trying; the agent keeps running"} {
		if !strings.Contains(body, want) {
			t.Errorf("a pause that failed lacks %q", want)
		}
	}
	appendLines(t, root, harmRun, pauseLine(11, time.Date(2026, 10, 25, 12, 2, 1, 0, time.UTC), "run-resumed", "resume"))

	// A pause the run has confirmed: what is frozen, what still runs, how to resume.
	appendLines(t, root, harmRun, pauseLine(12, time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC), "run-paused", "pause"))
	body = page()
	for _, want := range []string{"The agent is frozen where it stood", "Tego itself keeps running", "Resume lets it carry on"} {
		if !strings.Contains(body, want) {
			t.Errorf("a paused run lacks %q", want)
		}
	}
	for _, old := range []string{"Withdraw pause", "takes the request back", "withdraws the request"} {
		for _, b := range []string{body, page()} {
			if strings.Contains(b, old) {
				t.Errorf("the page still says %q", old)
			}
		}
	}
	// The record's own lines name the same thing.
	if got := gapWords("enforce", "pause-failed"); !strings.Contains(got, "did not take") || strings.Contains(got, "failed") {
		t.Errorf("pause-failed reads %q", got)
	}
}

// runningDriftFixture is a running enforced run whose contract grants two folders, one of them used.
func runningDriftFixture(t *testing.T) (root string, now time.Time) {
	t.Helper()
	root = t.TempDir()
	cwd := t.TempDir()
	for _, d := range []string{"out", "spare"} {
		if err := os.MkdirAll(filepath.Join(cwd, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	contract := "version: 0\nname: demo-drift\ncommand: [sh]\ncapture: off\nfs:\n  write: [./out, ./spare]\n"
	sum := sha256.Sum256([]byte(contract))
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	dir := filepath.Join(root, cleanRun)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lines := line(cleanRun, "demo-drift", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"cwd":"`+cwd+`","contract_hash":"`+hex.EncodeToString(sum[:])+`"`) +
		line(cleanRun, "demo-drift", 1, t0.Add(time.Second), "fs", `"verdict":"allow","rule":"fs.write[./out]","op":"open","path":"`+cwd+`/out/a","flags":577`)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	markLive(t, root, cleanRun)
	return root, t0.Add(time.Minute)
}

// TestRunningLeastPrivilegeSaysHowFarItReads (C118): a run that has not ended is read up to its newest line, and both
// results (the entries to remove, and the proposed contract) say so, with the time they cover, in the zone the page
// shows; an ended run's tab says nothing of the kind.
func TestRunningLeastPrivilegeSaysHowFarItReads(t *testing.T) {
	root, now := runningDriftFixture(t)
	s, err := New(Config{Ledger: root, Port: port, Token: "tok123", Machine: &config.Machine{Home: t.TempDir()}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	body := f3Text(do(s, "GET", "/runs/"+cleanRun+"/least-privilege", "127.0.0.1:8484", c).Body.String())
	if !strings.Contains(body, "Remove the") || !strings.Contains(body, "granted but never used") {
		t.Fatalf("the fixture shows no entries to remove: %s", body)
	}
	last := time.Date(2026, 10, 25, 12, 0, 1, 0, time.UTC).Local().Format("15:04:05")
	for _, want := range []string{
		"This run is still running, so this covers only what it did up to " + last,
		"The run has not ended: this covers only what it did up to " + last,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the tab lacks %q", want)
		}
	}
	if !strings.Contains(body, "may still use an entry it has not used yet") {
		t.Error("the caveat does not say an unused entry may still be used")
	}
	// The run ends: the same tab no longer qualifies.
	appendLines(t, root, cleanRun, line(cleanRun, "demo-drift", 2, time.Date(2026, 10, 25, 12, 0, 2, 0, time.UTC), "run_end", `"reason":"exit","exit_code":0`))
	if err := os.Remove(filepath.Join(root, ".live", cleanRun)); err != nil {
		t.Fatal(err)
	}
	if body = f3Text(do(s, "GET", "/runs/"+cleanRun+"/least-privilege", "127.0.0.1:8484", c).Body.String()); strings.Contains(body, "still running") {
		t.Error("an ended run's Least privilege still says it is running")
	}
}

// TestHighlightsSecretLeadsToNeverAllow (C131): a secret the run read, on a run with a contract the dashboard can edit,
// has a link in Highlights that opens the line that touched it with the block action picked, where the rule is
// made. A dashboard that edits no contracts, a run with no contract file and a secret that was only refused show none.
func TestHighlightsSecretLeadsToNeverAllow(t *testing.T) {
	root, _, proj := detailFixture(t)
	secret := filepath.Join(proj, "a", "b", ".env")
	// The fixture's first read is a plain file name: make it a secret by name.
	evs, err := os.ReadFile(filepath.Join(root, detailRun, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.Replace(string(evs), filepath.Join(proj, "a", "b", "secret.txt"), secret, 1)
	if err := os.WriteFile(filepath.Join(root, detailRun, "events.jsonl"), []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	page := func() string { return do(s, "GET", "/runs/"+detailRun, "127.0.0.1:8484", c).Body.String() }
	link := `href="/runs/` + detailRun + `/lines/1?a=block#act-check"`
	if strings.Contains(page(), "Secrets 1") == false && !strings.Contains(f3Text(page()), "Secrets 1") {
		t.Fatalf("the fixture shows no secret in Highlights: %s", f3Text(page()))
	}
	if b := page(); strings.Contains(b, link) {
		t.Error("a dashboard that edits no contract offers Never allow")
	}
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	b := page()
	if !strings.Contains(b, link) || !strings.Contains(b, ">Never allow<") {
		t.Errorf("the secret's row has no route to Never allow (%q)", link)
	}
	// The link opens a page that can make the rule.
	if body := do(s, "GET", "/runs/"+detailRun+"/lines/1?a=block", "127.0.0.1:8484", c).Body.String(); !strings.Contains(body, `id="act-check"`) {
		t.Error("the link's page has no panel to make the rule in")
	}
}

// TestAnswerErrSaysWhatIsTrueOfAGoneSocket (N125): a run whose launcher holds its lock but whose answer socket is not
// there (ENOENT) or has no listener (ECONNREFUSED) has not been shown to have ended, so the line must not say it is not
// running; a run with no live launcher is the one that says so. The words match `tego ask`'s: the answer was not delivered.
func TestAnswerErrSaysWhatIsTrueOfAGoneSocket(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"socket not there", fmt.Errorf("dial unix /run/x/ask.sock: %w", os.ErrNotExist), "answer socket is gone"},
		{"socket not there, wrapped by the client", fmt.Errorf("ask: %w", &os.PathError{Op: "connect", Path: "/run/x/ask.sock", Err: syscall.ENOENT}), "answer socket is gone"},
		{"nobody listens", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), "nothing is listening on the run's answer socket"},
		{"no live launcher", fmt.Errorf("run: %w", askclient.ErrNoBroker), "the run is not running"},
	} {
		got := answerErr(c.err)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q lacks %q", c.name, got, c.want)
		}
		if c.want != "the run is not running" && (strings.Contains(got, "not running") || !strings.Contains(got, "was not delivered") || !strings.Contains(got, "may still be waiting")) {
			t.Errorf("%s: %q says the run is not running, or not that the answer was not delivered", c.name, got)
		}
	}
}
