// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// appendLines adds ledger lines to run's events file in root.
func appendLines(t *testing.T, root, run string, ls ...string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(strings.Join(ls, "")); err != nil {
		t.Fatal(err)
	}
}

// pauseFixture is fixture with its live run's directory marked as a launcher that reads a pause makes it
// (liveblock.MarkControl); the shared fixture's run has no mark, as an older launcher's.
func pauseFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	if err := liveblock.MarkControl(filepath.Join(root, harmRun)); err != nil {
		t.Fatal(err)
	}
	return root
}

// answerAsk7 is the line that answers the fixture's waiting request, which otherwise keeps Pause from being offered.
func answerAsk7(t *testing.T, root string, seq int) {
	t.Helper()
	appendLines(t, root, harmRun, line(harmRun, "demo-harm", seq, time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC), "answer",
		`"ask_id":"ask-7","verdict":"allow"`))
}

// pauseLine is the launcher's gap line for a pause or a resume of the live run, asked from the dashboard by this uid.
func pauseLine(seq int, ts time.Time, why, op string) string {
	return line(harmRun, "demo-harm", seq, ts, "gap", fmt.Sprintf(
		`"what":"enforce","why":"%s","live_control":{"op":"%s","by":"uid:%d pid:9 dashboard","serial":%d,"at":"2026-10-25T12:00:00Z"}`,
		why, op, os.Getuid(), seq))
}

// TestPauseButtonAndBadge: a run with a waiting request offers no Pause and says why; once answered, it offers Pause
// beside Stop; once its launcher records the pause, its page says who paused it and when and offers Resume, and the
// Runs and Overview rows say Paused; a resume takes it back, and a pause that failed says so and offers Resume to
// withdraw it, naming a waiting request as the reason when there is one.
func TestPauseButtonAndBadge(t *testing.T) {
	root := pauseFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	page := func() string { return do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String() }
	body := page()
	if strings.Contains(body, `action="/runs/`+harmRun+`/pause"`) || !strings.Contains(body, "Answer its waiting request first; then Pause freezes it.") ||
		!strings.Contains(body, `type="button" disabled`) || !strings.Contains(body, `<span class="soft pause-why" id="pause-why">Answer the waiting request first</span>`) {
		t.Fatal("a run with a waiting request offers Pause, or does not say why it does not")
	}
	appendLines(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 1, 7, 0, time.UTC), "gap",
		`"what":"enforce","why":"pause-failed","live_control":{"op":"pause","by":"uid:1000 pid:9 cli","serial":1,"at":"2026-10-25T12:00:00Z"}`))
	if body = page(); !strings.Contains(body, "The agent waits on a request, and a request that waits cannot be frozen") {
		t.Error("a pause that failed on a waiting request does not say so")
	}
	appendLines(t, root, harmRun, pauseLine(8, time.Date(2026, 10, 25, 12, 1, 8, 0, time.UTC), "run-resumed", "resume"))
	answerAsk7(t, root, 9)
	body = page()
	if !strings.Contains(body, `action="/runs/`+harmRun+`/pause"`) || strings.Contains(body, `/resume"`) {
		t.Fatal("a running run's page lacks Pause, or offers Resume")
	}
	if i, j := strings.Index(body, `/pause"`), strings.Index(body, `href="/runs/`+harmRun+`/stop"`); i < 0 || j < i {
		t.Error("Pause is not beside Stop, before it")
	}
	if strings.Contains(do(s, "GET", "/runs/"+cleanRun, "127.0.0.1:8484", c).Body.String(), `/pause"`) {
		t.Error("an ended run offers Pause")
	}

	t0 := time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC)
	appendLines(t, root, harmRun, pauseLine(10, t0, "run-paused", "pause"))
	body = page()
	for _, want := range []string{`action="/runs/` + harmRun + `/resume"`, "Paused by you, from the dashboard at", "frozen where it stood", "(line #10)"} {
		if !strings.Contains(body, want) {
			t.Errorf("a paused run's page lacks %q", want)
		}
	}
	if strings.Contains(body, `action="/runs/`+harmRun+`/pause"`) {
		t.Error("a paused run still offers Pause")
	}
	for _, p := range []string{"/runs", "/"} {
		if b := do(s, "GET", p, "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, "b-paused") {
			t.Errorf("%s does not say the run is Paused", p)
		}
	}

	appendLines(t, root, harmRun, pauseLine(11, t0.Add(time.Second), "run-resumed", "resume"))
	if body = page(); strings.Contains(body, "Paused by") || !strings.Contains(body, `/pause"`) {
		t.Error("a resumed run still reads as paused")
	}
	appendLines(t, root, harmRun, pauseLine(12, t0.Add(2*time.Second), "pause-failed", "pause"))
	body = page()
	if !strings.Contains(body, "The pause did not take.") || !strings.Contains(body, "Tego keeps trying, at most 30 s apart, until it takes or you stop the run") ||
		!strings.Contains(body, `/resume"`) || strings.Contains(body, "Paused by") {
		t.Error("a failed pause is not said plainly, or offers no way to withdraw it")
	}
	if !strings.Contains(body, ">Withdraw pause<") || !strings.Contains(body, "The agent is still running; this withdraws the pause") ||
		strings.Contains(body, "carry on from where it stood") {
		t.Error("a failed pause's button reads as if the agent had stopped")
	}
	// The pause withdrawn: the launcher records run-resumed, and the run reads as running, not paused.
	appendLines(t, root, harmRun, pauseLine(13, t0.Add(3*time.Second), "run-resumed", "resume"))
	if body = page(); strings.Contains(body, "Paused by") || strings.Contains(body, "did not take") || !strings.Contains(body, `/pause"`) {
		t.Error("a withdrawn failed pause still reads as paused or failed")
	}
	if b := do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String(); strings.Contains(b, "b-paused") {
		t.Error("Runs says Paused for a run whose failed pause was withdrawn")
	}
}

// TestPauseAskedNotConfirmed: a pause in the overlay that the launcher has not answered reads as waiting for the run
// to confirm it, offers Cancel pause, and says what it means when no answer comes; the launcher's line ends it.
func TestPauseAskedNotConfirmed(t *testing.T) {
	root := pauseFixture(t)
	answerAsk7(t, root, 7)
	s := newServer(t, root)
	c := login(t, s)
	if _, err := liveblock.Update(context.Background(), filepath.Join(root, harmRun), harmRun, func(o *liveblock.Overlay) (bool, error) {
		_, ok := o.Pause(liveblock.By("dashboard"), time.Now())
		return ok, nil
	}); err != nil {
		t.Fatal(err)
	}
	page := func() string { return do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String() }
	body := page()
	for _, want := range []string{"waiting for the run to confirm it", "does not read pauses", ">Cancel pause<", `action="/runs/` + harmRun + `/resume"`} {
		if !strings.Contains(body, want) {
			t.Errorf("an unconfirmed pause's page lacks %q", want)
		}
	}
	if strings.Contains(body, "Paused by") || strings.Contains(body, `action="/runs/`+harmRun+`/pause"`) {
		t.Error("an unconfirmed pause reads as paused, or offers Pause again")
	}
	appendLines(t, root, harmRun, pauseLine(8, time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC), "run-paused", "pause"))
	if body = page(); strings.Contains(body, "waiting for the run to confirm") || !strings.Contains(body, "Paused by") {
		t.Error("the launcher's line did not end the wait")
	}
}

// TestPausePosts: Pause and Resume reach runact with the run and the direction, return to the run's page with a plain
// line, and an error reads without a package name.
func TestPausePosts(t *testing.T) {
	root := pauseFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	tok := csrfOf(t, s, c, "/runs/"+harmRun)
	var got []string
	pauseRun = func(_ context.Context, _, run string, on bool) (runact.Paused, error) {
		got = append(got, fmt.Sprintf("%s %v", run, on))
		if on {
			return runact.Paused{Run: run, Word: runact.WordPaused, Serial: 1}, nil
		}
		return runact.Paused{}, fmt.Errorf("runact: %w", runact.ErrPauseNotRunning)
	}
	t.Cleanup(func() { pauseRun = runact.Pause })
	b := follow(t, s, c, post(s, "/runs/"+harmRun+"/pause", url.Values{"csrf": {tok}}, own, "", c))
	if !strings.Contains(b, "Not done: demo-harm") || !strings.Contains(b, "waits on a request. Answer it first") || len(got) != 0 {
		t.Errorf("a pause of a run with a waiting request was not refused plainly (%d calls)", len(got))
	}
	answerAsk7(t, root, 7)
	b = follow(t, s, c, post(s, "/runs/"+harmRun+"/pause", url.Values{"csrf": {tok}}, own, "", c))
	if !strings.Contains(b, "Pause asked of demo-harm") {
		t.Error("a pause does not say what it asked")
	}
	b = follow(t, s, c, post(s, "/runs/"+harmRun+"/resume", url.Values{"csrf": {tok}}, own, "", c))
	if !strings.Contains(b, "Not done: the run is not running") || strings.Contains(b, "runact:") {
		t.Error("a refused resume is not said plainly")
	}
	if want := []string{harmRun + " true", harmRun + " false"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("runact got %q, want %q", got, want)
	}
	if w := post(s, "/runs/"+harmRun+"/pause", url.Values{"csrf": {"stale"}}, own, "", c); w.Code != 403 || len(got) != 2 {
		t.Errorf("a pause with a stale token: %d, %d calls", w.Code, len(got))
	}
}

// TestPauseOlderLauncher: a live run whose launcher did not mark that it reads a pause (an older Tego's) offers no
// Pause and no pause banner, though the run's overlay asks one, and runact's refusal reads plainly.
func TestPauseOlderLauncher(t *testing.T) {
	root := fixture(t)
	answerAsk7(t, root, 7)
	s := newServer(t, root)
	c := login(t, s)
	body := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(body, `href="/runs/`+harmRun+`/stop"`) {
		t.Fatal("the live run offers no Stop run")
	}
	if strings.Contains(body, `/pause"`) || strings.Contains(body, `/resume"`) || strings.Contains(body, "i-pause") {
		t.Error("a run whose launcher cannot pause it is offered Pause")
	}
	if _, err := liveblock.Update(context.Background(), filepath.Join(root, harmRun), harmRun, func(o *liveblock.Overlay) (bool, error) {
		_, ok := o.Pause(liveblock.By("cli"), time.Now())
		return ok, nil
	}); err != nil {
		t.Fatal(err)
	}
	if body = do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String(); strings.Contains(body, "waiting for the run to confirm") ||
		strings.Contains(body, "Cancel pause") {
		t.Error("an older launcher's run shows a pause banner")
	}
	tok := csrfOf(t, s, c, "/runs/"+harmRun)
	pauseRun = func(context.Context, string, string, bool) (runact.Paused, error) {
		return runact.Paused{}, fmt.Errorf("runact: %w", runact.ErrPauseUnsupported)
	}
	t.Cleanup(func() { pauseRun = runact.Pause })
	b := follow(t, s, c, post(s, "/runs/"+harmRun+"/pause", url.Values{"csrf": {tok}}, own, "", c))
	if !strings.Contains(b, "Not done: this run cannot be paused: an older Tego started it, it was adopted, or it has no cgroup of its own. Stop run ends it.") {
		t.Error("a pause of an older launcher's run is not refused plainly")
	}
}

// TestPausedBy: who asked, in plain words.
func TestPausedBy(t *testing.T) {
	me := fmt.Sprint(os.Getuid())
	for by, want := range map[string]string{
		"uid:" + me + " pid:9 dashboard": "you, from the dashboard",
		"uid:" + me + " pid:9 cli":       "you, from a terminal",
		"uid:4242 pid:9 cli":             "user 4242, from a terminal",
		"":                               "someone",
	} {
		if got := pausedBy(by); got != want {
			t.Errorf("pausedBy(%q) = %q, want %q", by, got, want)
		}
	}
}

// TestLostPausedRunWords: a run whose launcher died with its last recorded state paused reads "Lost, last recorded
// paused", not Paused or a bare Lost, and its page says that is the last state recorded, that whether its processes
// are still frozen is not known here, and names tego status and tego stop, with no Pause or Resume to offer. A lock
// still held by a process that is not the run's launcher reads the same (launcherGone). Once a sweep ends it, its
// orphaned end says the last recorded state was paused and the record was closed. Those lines do not record how
// cleanup ran or prove the processes stayed frozen. A run lost while running keeps the plain Lost words.
func TestLostPausedRunWords(t *testing.T) {
	check := func(t *testing.T, s *Server, c *http.Cookie) {
		t.Helper()
		body := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
		for _, want := range []string{
			">Lost, last recorded paused</span>",
			"<strong>Lost, last recorded paused.</strong> This run's launcher died, and the last state it recorded was paused, with no resume after it.",
			"Whether its processes are still frozen is not known here",
			`<span class="mono">tego status ` + harmRun + `</span> reads its scope`,
			`<span class="mono">tego stop ` + harmRun + `</span> ends what is left`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("the page of a lost run last recorded paused lacks %q", want)
			}
		}
		if strings.Contains(body, `/resume"`) || strings.Contains(body, `/pause"`) || strings.Contains(body, "Paused by") {
			t.Error("the page offers Resume or Pause, or says it is paused")
		}
		if runs := do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String(); !strings.Contains(runs, ">Lost, last recorded paused</span>") {
			t.Error("the Runs list does not say Lost, last recorded paused")
		}
	}
	root := pauseFixture(t)
	answerAsk7(t, root, 7)
	appendLines(t, root, harmRun, pauseLine(8, time.Date(2026, 10, 25, 12, 1, 8, 0, time.UTC), "run-paused", "pause"))

	t.Run("a lock another process holds", func(t *testing.T) {
		// The lock stays held (markLive's, in this process), but the process its line names is gone.
		gone := exec.Command("/bin/true")
		if err := gone.Run(); err != nil {
			t.Skipf("no /bin/true: %v", err)
		}
		line := runlock.LockInfo{PID: gone.Process.Pid, StartBootNS: 1}.String()
		if err := os.WriteFile(filepath.Join(root, harmRun, "lock"), []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		s := newServer(t, root)
		check(t, s, login(t, s))
	})

	letGo(filepath.Join(root, harmRun)) // the launcher's death
	s := newServer(t, root)
	c := login(t, s)
	check(t, s, c)

	// These historical lines carry no cleanup-method field. An older sweep could close this record after a
	// scope-read error, so the page cannot infer that cgroup.kill ran from the orphaned end alone.
	appendLines(t, root, harmRun,
		line(harmRun, "demo-harm", 9, time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC), "gap", `"what":"record","why":"launcher-lost"`),
		line(harmRun, "demo-harm", 10, time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC), "run_end", `"reason":"orphaned","exit_code":125`))
	body := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(body, "The run&#39;s launcher died, and the last state it recorded was paused, with no resume after it. Tego closed the orphaned record; its last lines may be missing.") ||
		strings.Contains(body, "cgroup.kill") || strings.Contains(body, "Lost, last recorded paused") || strings.Contains(body, "without letting them run again") {
		t.Error("an orphaned end of a run last recorded paused does not say what is known, or still reads lost")
	}

	// Lost while running: the plain words.
	root2 := fixture(t)
	answerAsk7(t, root2, 7)
	letGo(filepath.Join(root2, harmRun))
	s2 := newServer(t, root2)
	body = do(s2, "GET", "/runs/"+harmRun, "127.0.0.1:8484", login(t, s2)).Body.String()
	if !strings.Contains(body, ">Lost</span>") || strings.Contains(body, "last recorded paused") {
		t.Error("a run lost while running reads otherwise than Lost")
	}
}

// TestRunPageSaysTheLauncherIsUnknown: a running run whose launcher could not be judged says so, with the failed check
// and the fix, and is still shown running (nothing is ended on it).
func TestRunPageSaysTheLauncherIsUnknown(t *testing.T) {
	old := launcherUnknown
	launcherUnknown = func(string, string) string {
		return "runtime: the lock holder's identity cannot be read: permission denied"
	}
	t.Cleanup(func() { launcherUnknown = old })
	root := pauseFixture(t)
	s := newServer(t, root)
	body := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", login(t, s)).Body.String()
	if !strings.Contains(body, "<strong>Launcher not confirmed.</strong>") || !strings.Contains(body, "permission denied") ||
		!strings.Contains(body, "pid namespace") || !strings.Contains(body, "Stop run") {
		t.Error("the run page does not say its launcher could not be confirmed, or no longer offers Stop")
	}
}
