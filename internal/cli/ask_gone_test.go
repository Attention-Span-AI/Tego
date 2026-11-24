// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runlock"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The two windows at the end of a run in which the loser of a lost approve race (two answerers, one request) used to
// hear a wrong or raw error (N109). The winner's answer ends the run, so the broker closes its socket while the loser's
// command is in flight:
//
//   - the broker closes the connection with the loser's packet unread: the loser's recvmsg fails with "connection
//     reset by peer" (a raw [io] error, exit 125);
//   - the broker has already removed its socket while the launcher still holds the run's lock: the loser's dial fails
//     with ENOENT, which askAt read as "its contract has no ask rule", false for a run that served approvals.
//
// Both are now said from what the run's record proves at that moment, and from nothing else. No test sleeps: the
// fake broker closes only once the client's packet is queued (a blocking MSG_PEEK), and the end of the run is
// ordered by the code under test's own second look at the run's lock (askLauncherAgain).

const (
	goneAsk   = "q-0123456789abcdef0123456789abcd01"
	goneOther = "q-0123456789abcdef0123456789abcd02"
)

// goneRun is a running run (this process holds its lock) whose run_start says whether it served approvals, with the
// ledger lines given after it.
func goneRun(t *testing.T, serves bool, lines ...*record.Event) (id, dir string, w *ledger.Writer) {
	t.Helper()
	root := gcRoot(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id = string(rid)
	dir = filepath.Join(root, id)
	w, err = ledger.Open(dir, record.RunRef{ID: id, Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock", RecordMinor: record.MinorLearn,
		Capabilities: map[string]bool{"ask": serves}}); err != nil {
		t.Fatal(err)
	}
	start, err := tegoruntime.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteLockInfo([]byte((tegoruntime.LockInfo{PID: os.Getpid(), StartBootNS: start}).String())); err != nil {
		t.Fatal(err)
	}
	for _, e := range lines {
		if err = w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	return id, dir, w
}

// answeredBy is the broker's answer line for q: approved by the process uid:<uid> pid:<pid>.
func answeredBy(t *testing.T, q string, uid, pid int) *record.Event {
	t.Helper()
	e := answerLine(t, q, true, "", 0.129)
	var p map[string]any
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		t.Fatal(err)
	}
	p["by"] = fmt.Sprintf("uid:%d pid:%d", uid, pid)
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	return e
}

// endRun is the run ending: its ledger gets run_end and its lock is released, as the launcher's exit does.
func endRun(t *testing.T, w *ledger.Writer) {
	t.Helper()
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
}

// resettingBroker serves dir's ask socket as a broker that closes with the client's command unread: it sends the
// hello, waits until the client's packet is queued (a blocking MSG_PEEK, so no timing is involved), runs beforeClose
// and closes the connection. The client's recvmsg then fails with ECONNRESET, as the evidence's loser's did.
func resettingBroker(t *testing.T, dir string, readFirst bool, beforeClose func()) {
	t.Helper()
	f, addr, err := askclient.OpenSocketDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: addr, Net: "unixpacket"})
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		hello, _ := json.Marshal(askproto.Response{Ready: strings.Repeat("a", askproto.NonceLen)})
		if _, err = c.Write(hello); err != nil {
			return
		}
		raw, err := c.SyscallConn()
		if err != nil {
			return
		}
		var perr error
		flags := unix.MSG_PEEK | unix.MSG_DONTWAIT
		if readFirst {
			flags = unix.MSG_DONTWAIT // the packet is taken: the close that follows is clean, and the client reads io.EOF
		}
		if err = raw.Read(func(fd uintptr) bool {
			_, _, perr = unix.Recvfrom(int(fd), make([]byte, 4096), flags)
			return perr != unix.EAGAIN // false: the netpoller calls again when the packet arrives
		}); err != nil || perr != nil {
			return
		}
		if beforeClose != nil {
			beforeClose()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-served })
}

type goneCase struct {
	name    string
	lines   func(t *testing.T) []*record.Event
	ended   bool // the run ends before the loser looks again
	exit    int
	code    string   // the diagnostic code in brackets
	want    []string // each is a whole stderr line, or a substring of stderr when it starts with "~"
	refused []string // none of these appears
}

func goneCases() []goneCase {
	const notPending = "tego approve: ask: request is no longer pending [io]"
	return []goneCase{
		{name: "answered by another, run still ending", exit: identity.ExitError, code: "io", want: []string{notPending},
			refused: []string{"no ask rule", "has ended", "may not have been delivered"},
			lines: func(t *testing.T) []*record.Event {
				return []*record.Event{askLine(t, goneAsk), answeredBy(t, goneAsk, 0, os.Getpid()+1)}
			}},
		{name: "answered by another, run ended", ended: true, exit: identity.ExitError, code: "io", want: []string{notPending},
			refused: []string{"no ask rule", "may not have been delivered"},
			lines: func(t *testing.T) []*record.Event {
				return []*record.Event{askLine(t, goneAsk), answeredBy(t, goneAsk, 0, os.Getpid()+1)}
			}},
		{name: "answered by this command, reply lost", exit: identity.ExitError, code: "io", want: []string{"~tego approve: your answer was recorded on line #2"},
			refused: []string{"no longer pending", "no ask rule", "has ended"},
			lines: func(t *testing.T) []*record.Event {
				return []*record.Event{askLine(t, goneAsk), answeredBy(t, goneAsk, os.Geteuid(), os.Getpid())}
			}},
		{name: "unanswered, run ended", ended: true, exit: identity.ExitFinding, code: "not-running", want: []string{"tego approve: RUN has ended; nothing waits for an answer [not-running]"},
			refused: []string{"no ask rule", "no longer pending"},
			lines:   func(t *testing.T) []*record.Event { return []*record.Event{askLine(t, goneAsk)} }},
		{name: "unanswered, run not ended: nothing is claimed", exit: identity.ExitError, code: "io", want: []string{"~UNDELIVERED"},
			refused: []string{"no ask rule", "no longer pending", "has ended", "approved"},
			lines:   func(t *testing.T) []*record.Event { return []*record.Event{askLine(t, goneAsk)} }},
	}
}

func checkGone(t *testing.T, tc goneCase, run, undelivered string, code int, out, errs string) {
	t.Helper()
	if code != tc.exit || out != "" {
		t.Errorf("exit %d (want %d), stdout %q, stderr %q", code, tc.exit, out, errs)
	}
	lines := strings.Split(strings.TrimSpace(errs), "\n")
	for _, w := range tc.want {
		w = strings.ReplaceAll(strings.ReplaceAll(w, "RUN", run), "UNDELIVERED", undelivered)
		found := false
		if sub, ok := strings.CutPrefix(w, "~"); ok {
			found = strings.Contains(errs, sub)
		}
		for _, l := range lines {
			found = found || l == w
		}
		if !found {
			t.Errorf("stderr has no line or words %q:\n%s", w, errs)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(errs), "["+tc.code+"]") {
		t.Errorf("stderr does not end in [%s]: %q", tc.code, errs)
	}
	for _, r := range tc.refused {
		if strings.Contains(errs, r) {
			t.Errorf("stderr says %q, which the record does not prove: %s", r, errs)
		}
	}
}

// TestALostApproveRaceLoserHearsTheTruthWhenTheBrokerResetsIt: window one, the connection reset.
func TestALostApproveRaceLoserHearsTheTruthWhenTheBrokerResetsIt(t *testing.T) {
	for _, tc := range goneCases() {
		t.Run(tc.name, func(t *testing.T) {
			id, dir, w := goneRun(t, true, tc.lines(t)...)
			resettingBroker(t, dir, false, func() {
				if tc.ended {
					endRun(t, w)
				}
			})
			var out, errs bytes.Buffer
			code := askAt(t.Context(), "approve", id, dir, goneAsk, true, false, false, "", &out, &errs)
			checkGone(t, tc, id, "may not have been delivered", code, out.String(), errs.String())
		})
	}
}

// TestALostApproveRaceLoserHearsTheTruthWhenTheBrokerClosesWithNoReply: the same close once the broker has taken the
// packet (the client reads io.EOF), for the answered-by-another and the unanswered cases.
func TestALostApproveRaceLoserHearsTheTruthWhenTheBrokerClosesWithNoReply(t *testing.T) {
	for _, tc := range goneCases() {
		if tc.ended {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			id, dir, _ := goneRun(t, true, tc.lines(t)...)
			resettingBroker(t, dir, true, nil)
			var out, errs bytes.Buffer
			code := askAt(t.Context(), "approve", id, dir, goneAsk, true, false, false, "", &out, &errs)
			checkGone(t, tc, id, "may not have been delivered", code, out.String(), errs.String())
		})
	}
}

// TestALostApproveRaceLoserHearsTheTruthWhenTheSocketIsAlreadyGone: window two, the dial's ENOENT while the launcher
// still holds the run's lock. The run's own run_start says it served approvals, so "no ask rule" is never said.
func TestALostApproveRaceLoserHearsTheTruthWhenTheSocketIsAlreadyGone(t *testing.T) {
	for _, tc := range goneCases() {
		t.Run(tc.name, func(t *testing.T) {
			id, dir, w := goneRun(t, true, tc.lines(t)...)
			prev := askLauncherAgain
			askLauncherAgain = func(d string) (*runlock.StopTarget, error) {
				if tc.ended {
					endRun(t, w) // the run ends between the loser's dial and its second look
				}
				return prev(d)
			}
			t.Cleanup(func() { askLauncherAgain = prev })
			var out, errs bytes.Buffer
			code := askAt(t.Context(), "approve", id, dir, goneAsk, true, false, false, "", &out, &errs)
			checkGone(t, tc, id, "this answer was not delivered", code, out.String(), errs.String())
		})
	}
}

// A run that served approvals and holds no line for the id: the id was never one of its asks, so nothing was answered
// (not found), and still not "no ask rule".
func TestAnApproveOfAnIdTheServingRunNeverHeldIsNotSaidToHaveNoAskRule(t *testing.T) {
	id, dir, _ := goneRun(t, true, askLine(t, goneAsk))
	var out, errs bytes.Buffer
	code := askAt(t.Context(), "approve", id, dir, goneOther, true, false, false, "", &out, &errs)
	if code != identity.ExitFinding || out.Len() != 0 || strings.Contains(errs.String(), "no ask rule") || !strings.Contains(errs.String(), "[not-found]") ||
		!strings.Contains(errs.String(), goneOther) {
		t.Errorf("exit %d stdout %q stderr %q", code, &out, &errs)
	}
}

// A run whose run_start says it did not serve approvals keeps its words, and a run whose start cannot be read says
// nothing about its contract.
func TestNoApprovalsIsSaidOnlyOfARunWhoseStartSaysSo(t *testing.T) {
	id, dir, _ := goneRun(t, false)
	if got, none := noApprovalsWords(id, dir); got != id+" takes no approvals: its contract has no ask rule" || !none {
		t.Errorf("a run that did not serve approvals: %q %v", got, none)
	}
	idServing, dirServing, _ := goneRun(t, true)
	if got, none := noApprovalsWords(idServing, dirServing); strings.Contains(got, "no ask rule") || !strings.Contains(got, "ask socket is not there") || none {
		t.Errorf("a run that served approvals: %q %v", got, none)
	}
	idBare := "r-3f9c2a1b-0dllq06ts7599-k7m2pz"
	if got, none := noApprovalsWords(idBare, filepath.Join(t.TempDir(), idBare)); strings.Contains(got, "no ask rule") || none {
		t.Errorf("a run whose start is unreadable: %q %v", got, none)
	}
}

// The third window: the launcher the lock line names exits between the loser's look at the lock (held) and its look at the
// launcher (a pidfd of a process that has gone, or is going). That is the run ending, and `tego approve` said "the pid the
// lock file names ... [io]" for it (exit 125) instead of what it says of a run it finds ended.
func TestAnApproveOfARunWhoseLauncherLeftWhileItWasLookedAtSaysTheRunEnded(t *testing.T) {
	id, dir, w := goneRun(t, true, askLine(t, goneAsk))
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	start, err := tegoruntime.StartBootNS(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	pidfd, err := sys.PidfdOpenProcessFD(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pidfd.Close() })
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// Gone, and not reaped: its pidfd is readable, its /proc entry is still there. The run's lock stays held by this test.
	if err = pidfd.Borrow(func(fd int) error {
		for {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, perr := unix.Poll(fds, -1); perr == nil && n > 0 {
				return nil
			} else if perr != nil && perr != unix.EINTR {
				return perr
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err = w.WriteLockInfo([]byte((tegoruntime.LockInfo{PID: cmd.Process.Pid, StartBootNS: start}).String())); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := askAt(t.Context(), "approve", id, dir, goneAsk, true, false, false, "", &out, &errs)
	want := "tego approve: " + id + " has ended; nothing waits for an answer [not-running]"
	if code != identity.ExitFinding || out.Len() != 0 || strings.TrimSpace(errs.String()) != want {
		t.Errorf("exit %d stdout %q stderr %q, want exit 1 and %q", code, &out, &errs, want)
	}
}

// `tego ask` is not an answer: when the broker goes away under it, it does not say an answer may not have been delivered.
func TestAnAskOfARunWhoseBrokerGoesAwayDoesNotSpeakOfAnAnswer(t *testing.T) {
	id, dir, _ := goneRun(t, true, askLine(t, goneAsk))
	resettingBroker(t, dir, false, nil)
	var out, errs bytes.Buffer
	code := askAt(t.Context(), "ask", id, dir, goneAsk, false, false, false, "", &out, &errs)
	if code != identity.ExitError || out.Len() != 0 || strings.Contains(errs.String(), "this answer") || !strings.Contains(errs.String(), "[io]") {
		t.Errorf("exit %d stdout %q stderr %q", code, &out, &errs)
	}
}

func TestAnAskOfARunWhoseSocketIsGoneDoesNotSpeakOfAnAnswer(t *testing.T) {
	id, dir, _ := goneRun(t, true, askLine(t, goneAsk))
	var out, errs bytes.Buffer
	code := askAt(t.Context(), "ask", id, dir, goneAsk, false, false, false, "", &out, &errs)
	if code != identity.ExitError || out.Len() != 0 || strings.Contains(errs.String(), "this answer") || !strings.Contains(errs.String(), "ask socket is not there now") {
		t.Errorf("with the socket gone: exit %d stdout %q stderr %q", code, &out, &errs)
	}
}

// `tego ask <run> --json` of a run that served approvals and whose socket is gone says what the text form says, not an
// empty list that reads as nothing waiting (review F4); a run that takes no approvals keeps its empty list.
func TestAskJSONOfARunWhoseSocketIsGoneAgreesWithTheText(t *testing.T) {
	id, dir, _ := goneRun(t, true)
	var out, errs bytes.Buffer
	code := askAt(t.Context(), "ask", id, dir, "", false, false, true, "", &out, &errs)
	if code != identity.ExitFinding || out.Len() != 0 || !strings.Contains(errs.String(), "ask socket is not there now") || !strings.Contains(errs.String(), "[not-found]") {
		t.Errorf("serving run, socket gone, --json: exit %d stdout %q stderr %q", code, &out, &errs)
	}
	idNone, dirNone, _ := goneRun(t, false)
	out.Reset()
	errs.Reset()
	if code := askAt(t.Context(), "ask", idNone, dirNone, "", false, false, true, "", &out, &errs); code != identity.ExitOK || !strings.Contains(out.String(), `"pending":[]`) {
		t.Errorf("run with no ask rule, --json: exit %d stdout %q stderr %q", code, &out, &errs)
	}
}
