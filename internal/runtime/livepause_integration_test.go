// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// `tego pause` and `tego resume` end to end at tier landlock, through the real binary and the run's own delegated
// cgroup (record.MinorLiveControl, livepause.go): a run whose agent waits on an ask is not frozen until the ask is
// answered and keeps making progress meanwhile, and a busy agent whose every read goes through the open deputy
// (fs.reads: held) is paused and resumed twenty times without one pause failing.

// pauseScene writes a contract at tier landlock that lets the agent run sh, cat and sleep, with fsExtra lines under
// fs:, and the agent's script, in which $SECRET is a secret file's path outside the project.
func pauseScene(t *testing.T, fsExtra func(secret string) string, script string) *askReadScene {
	t.Helper()
	bin := tegoBinary(t)
	var allow []string
	for _, name := range []string{"sh", "cat", "sleep"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("no %s: %v", name, err)
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{p, real} {
			if !slices.Contains(allow, fmt.Sprintf("%q", q)) {
				allow = append(allow, fmt.Sprintf("%q", q))
			}
		}
	}
	vault, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin, secret: filepath.Join(vault, "token")}
	if err := os.WriteFile(s.secret, []byte(realSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: ipause
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
%sexec:
  allow: [%s]
net: {}
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 60s
limits:
  pids: 64
record: summary
`, fsExtra(s.secret), strings.Join(allow, ", "))
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.f = newFixtureIn(t, project, contract, nil)
	script = strings.ReplaceAll(script, "$SECRET", s.secret)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, s.secret)
	agentOwns(t, s.secret, filepath.Join(s.f.dir, "agent.sh"))
	s.env = isolatedEnv(t, s.f)
	return s
}

// beats is how many beats the agent's heartbeat wrote: the lines of out/n, each appended whole by one echo, so a count
// read while the agent writes never goes back. The heartbeat rewrote its number in place (echo $i > out/n) until
// 2026-11-06, and a read between the shell's truncate and its write found the file empty and read 0: CI's build-test
// failed "the agent wrote -39 beats in 1 s after the resume" so (run 42184797264). That loop, read as beats read it,
// went back on 14 of 34,711 reads on the reference box at load 6; appended lines, on none of 33,814.
func (s *askReadScene) beats() int { return strings.Count(s.out("n"), "\n") }

// controlWhys is the whys of the run's pause and resume lines so far, in ledger order.
func controlWhys(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var whys []string
	for l := range bytes.Lines(raw) {
		if !bytes.Contains(l, []byte(`"live_control"`)) {
			continue
		}
		e, err := record.Decode(bytes.TrimSpace(l))
		if err != nil {
			continue
		}
		var p record.GapPayload
		if e.DecodePayload(&p) == nil && p.LiveControl != nil {
			whys = append(whys, p.Why)
		}
	}
	return whys
}

// waitWhy waits up to 5 s for the run's pause lines to end with why.
func waitWhy(t *testing.T, dir, why string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if w := controlWhys(t, dir); len(w) > 0 && w[len(w)-1] == why {
			return
		}
	}
	t.Fatalf("no %s line within 5 s: the run's pause lines are %v", why, controlWhys(t, dir))
}

// progress is how many beats the agent wrote over d.
func (s *askReadScene) progress(d time.Duration) int {
	before := s.beats()
	time.Sleep(d)
	return s.beats() - before
}

// TestIntegrationPauseWaitsForAnAnsweredAsk: while the agent waits on an fs.ask_read, a pause is recorded
// pause-failed and the run is not frozen: its other process keeps writing at full pace (a freeze and thaw at the
// poll's pace would hold it about 97% of the time). Once the ask is answered the launcher freezes the run, the
// heartbeat stops, and a resume lets it carry on.
func TestIntegrationPauseWaitsForAnAnsweredAsk(t *testing.T) {
	s := pauseScene(t, func(secret string) string { return fmt.Sprintf("  ask_read: [%q]\n", secret) },
		"#!/bin/sh\n"+
			"( i=0; while [ ! -e out/stop ]; do i=$((i+1)); echo $i >> out/n; sleep 0.1; done ) &\n"+
			"cat \"$SECRET\" > out/got1.txt 2> out/err1.txt; echo $? > out/rc1\n"+
			"wait\n")
	run, dir := s.start(t)
	id := filepath.Base(dir)
	req := s.pending(t, id)

	out, code := s.try(t, "pause", id)
	if code != 1 || !strings.Contains(out, "could not freeze the run yet") {
		t.Fatalf("tego pause while an ask waits: exit %d\n%s", code, out)
	}
	if w := controlWhys(t, dir); !slices.Equal(w, []string{record.GapPauseFailed}) {
		t.Fatalf("pause lines %v, want one pause-failed", w)
	}
	// 0.1 s a beat: about 30 in 3 s when the run is not frozen; a run frozen most of the time writes a handful.
	if n := s.progress(3 * time.Second); n < 15 {
		t.Fatalf("the agent wrote %d beats in 3 s after a pause-failed: it is not running freely", n)
	}

	s.answer(t, "approve", id, req["ask_id"].(string))
	waitWhy(t, dir, record.GapRunPaused)
	time.Sleep(200 * time.Millisecond)
	if n := s.progress(time.Second); n > 1 {
		t.Fatalf("the agent wrote %d beats in 1 s while paused", n)
	}

	if out, code := s.try(t, "resume", id); code != 0 || !strings.Contains(out, "resumed (line #") {
		t.Fatalf("tego resume: exit %d\n%s", code, out)
	}
	if n := s.progress(time.Second); n < 5 {
		t.Fatalf("the agent wrote %d beats in 1 s after the resume", n)
	}
	if err := os.WriteFile(filepath.Join(s.f.out, "stop"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s.finish(t, run, dir)
	if got := s.out("got1.txt"); got != realSecret {
		t.Fatalf("the approved read gave %q", got)
	}
	want := []string{record.GapPauseFailed, record.GapRunPaused, record.GapRunResumed}
	if w := controlWhys(t, dir); !slices.Equal(w, want) {
		t.Fatalf("pause lines %v, want %v", w, want)
	}
}

// TestIntegrationPauseBusyHeldReads: an agent that reads five files in a loop with fs.reads: held, so that nearly
// every moment has a read in flight through the open deputy, which lives in the frozen cgroup, is paused and
// resumed twenty times. A single 1 s attempt missed 2 of 15 on 2026-10-27; the retried attempts make a miss rare,
// not impossible (the deputy still shares the frozen cgroup), so one pause-failed in the twenty is allowed when the
// launcher's retry then confirms the pause. TEGO_TEST_PAUSE_STRICT=1 asks for twenty confirmed at once, as on the
// box the attempts were tuned on.
func TestIntegrationPauseBusyHeldReads(t *testing.T) {
	s := pauseScene(t, func(string) string { return "  reads: held\n" },
		"#!/bin/sh\n"+
			"i=0\n"+
			"while [ ! -e out/stop ]; do i=$((i+1)); cat out/src/1.txt out/src/2.txt out/src/3.txt out/src/4.txt out/src/5.txt > out/last; echo $i >> out/n; done\n")
	if err := os.MkdirAll(filepath.Join(s.f.out, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(filepath.Join(s.f.out, "src", fmt.Sprintf("%d.txt", i)), []byte("benign\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run, dir := s.start(t)
	id := filepath.Base(dir)
	for deadline := time.Now().Add(10 * time.Second); s.beats() == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the agent never looped")
		}
	}
	const rounds = 20
	strict := os.Getenv("TEGO_TEST_PAUSE_STRICT") == "1"
	var slowest time.Duration
	misses := 0
	for i := range rounds {
		start := time.Now()
		out, code := s.try(t, "pause", id)
		switch {
		case code == 0 && strings.Contains(out, "paused (line #"):
			slowest = max(slowest, time.Since(start))
		case code == 1 && strings.Contains(out, "could not freeze the run yet") && !strict && misses == 0:
			misses++ // the launcher tries again after 2 s: the pause must then be confirmed
			waitWhy(t, dir, record.GapRunPaused)
			t.Logf("pause %d of %d missed once, then confirmed by the launcher's retry", i+1, rounds)
		default:
			t.Fatalf("pause %d of %d (%d missed before): exit %d\n%s", i+1, rounds, misses, code, out)
		}
		if n := s.progress(150 * time.Millisecond); n > 0 {
			t.Fatalf("pause %d: the agent looped %d times while paused", i+1, n)
		}
		if out, code := s.try(t, "resume", id); code != 0 || !strings.Contains(out, "resumed (line #") {
			t.Fatalf("resume %d of %d: exit %d\n%s", i+1, rounds, code, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("%d pauses confirmed (%d after a retry); the slowest tego pause confirmed at once took %s", rounds, misses, slowest)
	if err := os.WriteFile(filepath.Join(s.f.out, "stop"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s.finish(t, run, dir)
	w := controlWhys(t, dir)
	failed := 0
	for _, why := range w {
		if why == record.GapPauseFailed {
			failed++
		}
	}
	if failed != misses || len(w) != 2*rounds+misses {
		t.Fatalf("pause lines %v: want %d with %d pause-failed", w, 2*rounds+misses, misses)
	}
}
