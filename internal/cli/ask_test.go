// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestAskCommandsValidateArgumentsWithoutAccountState(t *testing.T) {
	for _, tc := range []struct {
		command Command
		args    []string
	}{{cmdAsk(), []string{"bad-run"}}, {cmdApprove(), []string{"r-1"}}, {cmdDeny(), []string{"bad-run", "q-invalid"}}, {cmdAsk(), []string{"r-3f9c2a1b-0dllq06ts7400-k7m2pq", "q-invalid"}}, {cmdApprove(), []string{"r-3f9c2a1b-0dllq06ts7400-k7m2pq", ""}}} {
		f := flag.NewFlagSet(tc.command.Name, flag.ContinueOnError)
		tc.command.Flags(f)
		_ = f.Parse(tc.args)
		var out, errs bytes.Buffer
		if code := tc.command.Run(context.Background(), f, &out, &errs); code != identity.ExitUsage || out.Len() != 0 || !strings.Contains(errs.String(), "[usage]") {
			t.Fatalf("%s exit%d out=%s err=%s", tc.command.Name, code, &out, &errs)
		}
	}
}

// These commands use only a private ledger with a no-op anchor. Its actual
// flock and launcher birth are verified before the real broker exchange.
func TestAskCLIActualPrivateBrokerListDetailAnswerAndCompletedRefusal(t *testing.T) {
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	dir := filepath.Join(t.TempDir(), id)
	w, e := ledger.Open(dir, record.RunRef{ID: id, Agent: "test"}, ledger.WithAnchor(nopAnchor{}))
	if e != nil {
		t.Fatal(e)
	}
	defer w.Abandon()
	start, e := tegoruntime.StartBootNS(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	if e = w.WriteLockInfo([]byte((tegoruntime.LockInfo{PID: os.Getpid(), StartBootNS: start}).String())); e != nil {
		t.Fatal(e)
	}
	broker, e := ask.New(dir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Second, Authorize: func(ask.Peer) error { return nil }, Emit: func(ask.Event) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	decision := make(chan ask.Decision, 1)
	go func() {
		d, _ := broker.Request(t.Context(), ask.Request{Op: "open", Target: "/private/\x1b[31mfile", Rule: "fs.ask", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()})
		decision <- d
	}()
	var out, errs bytes.Buffer
	var pending struct {
		Pending []ask.Summary `json:"pending"`
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		out.Reset()
		errs.Reset()
		if code := askAt(t.Context(), "ask", id, dir, "", false, false, true, "", &out, &errs); code != 0 {
			t.Fatalf("list exit%d %s", code, &errs)
		}
		if e = json.Unmarshal(out.Bytes(), &pending); e != nil {
			t.Fatal(e)
		}
		if len(pending.Pending) == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(pending.Pending) != 1 {
		t.Fatal("pending request absent")
	}
	askID := pending.Pending[0].AskID
	out.Reset()
	errs.Reset()
	if code := askAt(t.Context(), "ask", id, dir, askID, false, false, false, "", &out, &errs); code != 0 || strings.Contains(out.String(), "\x1b") {
		t.Fatalf("detail exit%d out=%q err=%s", code, out.String(), &errs)
	}
	out.Reset()
	errs.Reset()
	if code := askAt(t.Context(), "approve", id, dir, askID, true, false, true, "", &out, &errs); code != 0 {
		t.Fatalf("answer exit%d %s", code, &errs)
	}
	if d := <-decision; !d.Approved || d.AskID != askID {
		t.Fatalf("decision %+v", d)
	}
	out.Reset()
	errs.Reset()
	if code := askAt(t.Context(), "deny", id, dir, askID, false, false, false, "", &out, &errs); code != identity.ExitError {
		t.Fatalf("reanswer exit%d out=%s err=%s", code, &out, &errs)
	}
}

// newCLIBroker is a broker on a private ledger directory with a no-op anchor, as the test above builds it.
func newCLIBroker(t *testing.T, id string, emit func(ask.Event) error) (string, *ask.Broker) {
	t.Helper()
	return newCLIBrokerIn(t, t.TempDir(), id, emit)
}

// newCLIBrokerIn is newCLIBroker for the run id under the ledger root root.
func newCLIBrokerIn(t *testing.T, root, id string, emit func(ask.Event) error) (string, *ask.Broker) {
	t.Helper()
	dir := newCLIRunIn(t, root, id)
	broker, err := ask.New(dir, ask.Options{UID: uint32(os.Getuid()), Timeout: 5 * time.Second, Authorize: func(ask.Peer) error { return nil }, Emit: emit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	return dir, broker
}

// newCLIRunIn is a running run under root whose launcher is this test process and that serves no ask socket, as a run
// whose contract has no ask rule, or a watched run, serves none.
func newCLIRunIn(t *testing.T, root, id string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "test"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	start, err := tegoruntime.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteLockInfo([]byte((tegoruntime.LockInfo{PID: os.Getpid(), StartBootNS: start}).String())); err != nil {
		t.Fatal(err)
	}
	return dir
}

// pendingAskID waits for the one request the broker holds and returns its ask id.
func pendingAskID(t *testing.T, id, dir string) string {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		var out, errs bytes.Buffer
		if code := askAt(t.Context(), "ask", id, dir, "", false, false, true, "", &out, &errs); code != 0 {
			t.Fatalf("list exit%d %s", code, &errs)
		}
		var pending struct {
			Pending []ask.Summary `json:"pending"`
		}
		if err := json.Unmarshal(out.Bytes(), &pending); err != nil {
			t.Fatal(err)
		}
		if len(pending.Pending) == 1 {
			return pending.Pending[0].AskID
		}
	}
	t.Fatal("no request is pending")
	return ""
}

// `approve --always` and `deny --always` end to end over the real socket: the person is told the answer stands, the
// next identical request is answered without a hold and cites the answer, and a hold that cannot be remembered is
// refused the flag with the request still pending (so the same command without it answers it).
func TestAskCLIAlwaysAnswersStandAndAreSaid(t *testing.T) {
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	var mu sync.Mutex
	var lines []ask.Event
	dir, broker := newCLIBroker(t, id, func(e ask.Event) error {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, e)
		return nil
	})
	request := func(op, target, hold string) (ask.Decision, error) {
		return broker.Request(t.Context(), ask.Request{Op: op, Target: target, Rule: "fs.ask", Hold: hold, PID: os.Getpid(), TID: os.Getpid()})
	}
	held := func(op, target, hold string) <-chan ask.Decision {
		c := make(chan ask.Decision, 1)
		go func() { d, _ := request(op, target, hold); c <- d }()
		return c
	}
	answer := func(name string, approve, always bool) (int, string, string) {
		var out, errs bytes.Buffer
		code := askAt(t.Context(), name, id, dir, pendingAskID(t, id, dir), approve, always, false, "", &out, &errs)
		return code, out.String(), errs.String()
	}

	first := held("open", "/w/a.txt", ask.HoldOpen)
	code, out, errs := answer("approve", true, true)
	if code != 0 || !strings.Contains(out, ": approved, and every later request for the same operation, rule and target in this run") {
		t.Fatalf("approve --always: exit%d out=%q err=%q", code, out, errs)
	}
	if d := <-first; !d.Approved || !d.Always {
		t.Fatalf("the answered request = %+v", d)
	}
	again, err := request("open", "/w/a.txt", ask.HoldOpen) // no hold, no person
	if err != nil || !again.Approved || !strings.HasPrefix(again.By, "standing:") || !again.Always {
		t.Fatalf("the identical request = %+v, %v; want a standing approval", again, err)
	}
	other := held("open", "/w/other.txt", ask.HoldOpen)
	if code, out, errs = answer("deny", false, true); code != 0 || !strings.Contains(out, ": denied, and every later request for the same operation, rule and target in this run") {
		t.Fatalf("deny --always: exit%d out=%q err=%q", code, out, errs)
	}
	if d := <-other; d.Approved || d.Reason != ask.ReasonDenied || !d.Always {
		t.Fatalf("the denied request = %+v", d)
	}
	if again, err = request("open", "/w/other.txt", ask.HoldOpen); err != nil || again.Approved || again.Reason != ask.ReasonDenied || !strings.HasPrefix(again.By, "standing:") {
		t.Fatalf("the identical denied request = %+v, %v; want a standing denial", again, err)
	}

	// A first write is bound to the bytes the person saw: --always is refused, the request stays pending, and the
	// command without it answers it once.
	write := held("write", "/w/new.txt", "first_write")
	code, out, errs = answer("approve", true, true)
	if code == 0 || !strings.Contains(errs, "it is still pending, so answer it without --always") || out != "" {
		t.Fatalf("--always on a first_write: exit%d out=%q err=%q", code, out, errs)
	}
	if code, out, errs = answer("approve", true, false); code != 0 || strings.Contains(out, "every later request") || !strings.Contains(out, ": approved") {
		t.Fatalf("approve without --always: exit%d out=%q err=%q", code, out, errs)
	}
	if d := <-write; !d.Approved || d.Always {
		t.Fatalf("the first write's decision = %+v", d)
	}

	mu.Lock()
	defer mu.Unlock()
	standing := 0
	for _, e := range lines {
		if e.Kind == "answer" && strings.HasPrefix(e.Decision.By, "standing:") {
			standing++
		}
	}
	if standing != 2 {
		t.Fatalf("%d standing answer lines in the ledger events, want 2 (one approval, one denial)", standing)
	}
}

// A second --always for a key whose standing answer is still being recorded is refused with a message that says the
// request is still pending, and the person is not told a denial stands while another answer's approval does.
func TestAskCLISecondAlwaysWhileTheFirstIsBeingRecordedIsRefused(t *testing.T) {
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	release, blocked := make(chan struct{}), make(chan struct{})
	var once sync.Once
	dir, broker := newCLIBroker(t, id, func(e ask.Event) error {
		if e.Kind == "answer" && strings.HasSuffix(e.Decision.By, " always") {
			once.Do(func() { close(blocked) })
			<-release
		}
		return nil
	})
	req := ask.Request{Op: "open", Target: "/w/a.txt", Rule: "fs.ask", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()}
	decisions := make(chan ask.Decision, 2)
	for range 2 {
		go func() { d, _ := broker.Request(t.Context(), req); decisions <- d }()
	}
	var ids []string
	for deadline := time.Now().Add(2 * time.Second); len(ids) < 2 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		items, err := ask.ListFor(t.Context(), dir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		ids = ids[:0]
		for _, it := range items {
			ids = append(ids, it.AskID)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("held = %v, want two", ids)
	}
	first := make(chan string, 1)
	go func() {
		var out, errs bytes.Buffer
		askAt(t.Context(), "approve", id, dir, ids[0], true, true, false, "", &out, &errs)
		first <- out.String()
	}()
	<-blocked
	var out, errs bytes.Buffer
	code := askAt(t.Context(), "deny", id, dir, ids[1], false, true, false, "", &out, &errs)
	if code == 0 || out.Len() != 0 || !strings.Contains(errs.String(), "being recorded") || !strings.Contains(errs.String(), "still pending") {
		t.Fatalf("second --always: exit%d out=%q err=%q; want a refusal that says the request is still pending", code, out.String(), errs.String())
	}
	close(release)
	if got := <-first; !strings.Contains(got, ": approved, and every later request") {
		t.Fatalf("the first --always printed %q", got)
	}
	for range 2 {
		if d := <-decisions; !d.Approved {
			t.Fatalf("a request for the key = %+v, want the approval that stands", d)
		}
	}
}

func TestAnswerWordSaysWhatHappenedNotWhatWasAsked(t *testing.T) {
	const later = ", and every later request for the same operation, rule and target in this run"
	for name, tc := range map[string]struct {
		d     ask.Decision
		asked bool
		want  string // the whole word, or a prefix when it ends with "..."
	}{
		"approved":                     {ask.Decision{Approved: true}, false, "approved"},
		"denied":                       {ask.Decision{Reason: ask.ReasonDenied}, false, "denied"},
		"approved and standing":        {ask.Decision{Approved: true, Always: true}, true, "approved" + later},
		"denied and standing":          {ask.Decision{Reason: ask.ReasonDenied, Always: true}, true, "denied" + later},
		"an always that did not stand": {ask.Decision{Approved: true}, true, "approved, for this request only: the answer could not be made to stand for later requests"},
		"a denial that did not stand":  {ask.Decision{Reason: ask.ReasonDenied}, true, "denied, for this request only: ..."},
		"timed out first":              {ask.Decision{Reason: ask.ReasonTimeout}, false, "not approved: the hold timed out first, so ..."},
		"run ended":                    {ask.Decision{Reason: ask.ReasonUnavailable, By: "shutdown"}, false, "not approved: the answer could not be kept (..."},
		"unrecorded stays unstood":     {ask.Decision{Reason: ask.ReasonUnavailable}, true, "not approved: the answer could not be kept (..."},
		"timed out never stands":       {ask.Decision{Reason: ask.ReasonTimeout}, true, "not approved: the hold timed out first, so ..."},
		// The broker keeps Always only on a decision whose " always" line was recorded and installed: the request
		// ended after its line, and the answer stands though this operation was refused.
		"cancelled after its line": {ask.Decision{Reason: ask.ReasonUnavailable, By: "cancelled", Always: true}, true, "recorded, and stands for every later request for the same operation, rule and target in this run; this request itself ended after your answer was recorded, so its operation was refused"},
	} {
		got := answerWord(tc.d, tc.asked)
		want, prefix := strings.CutSuffix(tc.want, "...")
		if (!prefix && got != want) || (prefix && !strings.HasPrefix(got, want)) {
			t.Errorf("%s: answerWord(%+v, %v) = %q; want %q", name, tc.d, tc.asked, got, tc.want)
		}
		if !tc.d.Approved && strings.HasPrefix(got, "approved") {
			t.Errorf("%s: a decision that approved nothing reads %q", name, got)
		}
	}
}

// `tego alternate` end to end over the real socket: a held read is listed as a read, the person names a stand-in,
// is told plainly what was given in place of what, and the held request gets the stand-in; with --always the next
// identical request is given it at once; an alternate the open's own check refuses, or one for a request that takes
// none, leaves the request pending with a message that says so.
func TestAskCLIAlternateAnswersAHeldOpenWithAnotherFile(t *testing.T) {
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	dir, broker := newCLIBroker(t, id, func(ask.Event) error { return nil })
	files := t.TempDir()
	if err := os.Mkdir(filepath.Join(files, ".tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	chain, fake := filepath.Join(files, ".tego", "chain.log"), filepath.Join(files, "fake-credentials")
	for _, p := range []string{chain, fake, filepath.Join(files, "x")} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(files, filepath.Join(files, "link")); err != nil {
		t.Fatal(err)
	}
	refusal := errors.New(chain + " lies inside tego's own state")
	read := ask.Request{Op: ask.OpRead, Target: "/home/u/.aws/credentials", Rule: "fs.ask_read[~/.aws/credentials]", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid(),
		Alternates: ask.NewAlternateCheck(func(a *ask.AlternateFile) (string, error) {
			if strings.Contains(a.Named, ".tego") {
				return "", refusal
			}
			return a.Named, nil
		})}
	held := func(req ask.Request) <-chan ask.Decision {
		c := make(chan ask.Decision, 1)
		go func() { d, _ := broker.Request(t.Context(), req); c <- d }()
		return c
	}
	run := func(name, alternate string, approve, always bool) (int, string, string) {
		var out, errs bytes.Buffer
		code := askAt(t.Context(), name, id, dir, pendingAskID(t, id, dir), approve, always, false, alternate, &out, &errs)
		return code, out.String(), errs.String()
	}

	first := held(read)
	_ = pendingAskID(t, id, dir)
	var out, errs bytes.Buffer
	if code := askAt(t.Context(), "ask", id, dir, "", false, false, false, "", &out, &errs); code != 0 || !strings.Contains(out.String(), " open read /home/u/.aws/credentials") {
		t.Fatalf("the listing %q (exit %d): a held read says read", out.String(), code)
	}
	code, o, e := run("alternate", chain, false, false)
	if code == 0 || !strings.Contains(e, "the alternate cannot be used") || !strings.Contains(e, "tego's own state") || !strings.Contains(e, "still pending") || o != "" {
		t.Fatalf("a refused alternate: exit%d out=%q err=%q", code, o, e)
	}
	// A path through a symbolic link is refused by the command itself, which names where it resolves to.
	code, o, e = run("alternate", filepath.Join(files, "link", "fake-credentials"), false, false)
	if code != identity.ExitUsage || !strings.Contains(e, "no symbolic link") || !strings.Contains(e, fake) || !strings.Contains(e, "still pending") || o != "" {
		t.Fatalf("an alternate through a link: exit%d out=%q err=%q", code, o, e)
	}
	code, o, e = run("alternate", "/nonexistent/stand-in", false, false)
	if code == 0 || !strings.Contains(e, "no such file") || !strings.Contains(e, "still pending") {
		t.Fatalf("a missing alternate: exit%d out=%q err=%q", code, o, e)
	}
	code, o, e = run("alternate", fake, false, false)
	if code != 0 || !strings.Contains(o, ": gave "+fake+" in place of the file the agent asked for") || strings.Contains(o, "later request") {
		t.Fatalf("an alternate: exit%d out=%q err=%q", code, o, e)
	}
	if d := <-first; d.Alternate != fake || d.Approved || d.File == nil {
		t.Fatalf("the held read = %+v", d)
	} else {
		d.CloseAlternate()
	}

	second := held(read)
	code, o, e = run("alternate", fake, false, true)
	if code != 0 || !strings.Contains(o, "gives it again for every later request for the same operation, rule and target in this run") {
		t.Fatalf("an always alternate: exit%d out=%q err=%q", code, o, e)
	}
	sd := <-second
	sd.CloseAlternate()
	again, err := broker.Request(t.Context(), read)
	if err != nil || again.Alternate != fake || !strings.HasPrefix(again.By, "standing:") || again.File == nil {
		t.Fatalf("the identical read after --always = %+v, %v", again, err)
	}
	again.CloseAlternate()

	connect := held(ask.Request{Op: "connect", Target: "192.0.2.1:443", Rule: "net.ask[tcp://192.0.2.1:443]", Hold: "connect", PID: os.Getpid(), TID: os.Getpid()})
	code, _, e = run("alternate", filepath.Join(files, "x"), false, false)
	if code == 0 || !strings.Contains(e, "only a held file open takes one") || !strings.Contains(e, "still pending") {
		t.Fatalf("an alternate for a connect: exit%d err=%q", code, e)
	}
	if code, _, e = run("deny", "", false, false); code != 0 {
		t.Fatalf("deny after the refused alternate: exit%d %s", code, e)
	}
	<-connect
}

// The command's own arguments: a run, an ask id and --file are required, and a path with a control character is a
// usage error before any account state is read. A relative --file is taken from the command's directory.
func TestAlternateCommandArguments(t *testing.T) {
	for _, args := range [][]string{{"r-3f9c2a1b-0dllq06ts7400-k7m2pq", "q-" + strings.Repeat("0", 32)}, {"r-1", "--file", "/tmp/x"}, {"r-3f9c2a1b-0dllq06ts7400-k7m2pq", "q-" + strings.Repeat("0", 32), "--file", "/tmp/a\nb"}} {
		c := cmdAlternate()
		f := flag.NewFlagSet(c.Name, flag.ContinueOnError)
		c.Flags(f)
		if err := parseArgs(f, args, 0); err != nil {
			t.Fatal(err)
		}
		var out, errs bytes.Buffer
		if code := c.Run(context.Background(), f, &out, &errs); code != identity.ExitUsage || !strings.Contains(errs.String(), "[usage]") {
			t.Fatalf("%q: exit%d err=%s", args, code, &errs)
		}
	}
}

func TestAlternateWordSaysWhatWasGiven(t *testing.T) {
	for name, tc := range map[string]struct {
		d     ask.Decision
		asked bool
		want  string
	}{
		"given":                    {ask.Decision{Alternate: "/tmp/fake"}, false, "gave /tmp/fake in place of the file the agent asked for"},
		"given and standing":       {ask.Decision{Alternate: "/tmp/fake", Always: true}, true, "gave /tmp/fake in place of the file the agent asked for, and gives it again for every later request for the same operation, rule and target in this run"},
		"did not stand":            {ask.Decision{Alternate: "/tmp/fake"}, true, "gave /tmp/fake in place of the file the agent asked for, for this request only: the answer could not be made to stand for later requests"},
		"timed out first":          {ask.Decision{Reason: ask.ReasonTimeout}, true, "not given: the hold timed out first, so the operation was refused"},
		"not kept":                 {ask.Decision{Reason: ask.ReasonUnavailable}, false, "not given: the answer could not be kept (the run ended, was cancelled, or its ledger refused the line), so the operation was refused"},
		"cancelled after its line": {ask.Decision{Reason: ask.ReasonUnavailable, By: "cancelled", Always: true}, true, "recorded, and gives the file for every later request for the same operation, rule and target in this run; this request itself ended after your answer was recorded, so its operation was refused"},
		"escape":                   {ask.Decision{Alternate: "/tmp/\x1b[31mx"}, false, "gave /tmp/\\x1b[31mx in place of the file the agent asked for"},
	} {
		if got := alternateWord(tc.d, tc.asked); got != tc.want {
			t.Errorf("%s: %q\nwant %q", name, got, tc.want)
		}
	}
}

// TestAskCLISaysWhomTheBrokerServes: a person whose list or answer the broker refused (an agent's, inside a run, or
// one in another cgroup namespace) is told whom the run's broker serves and that what the run
// holds is still pending.
func TestAskCLISaysWhomTheBrokerServes(t *testing.T) {
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pr"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "test"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	start, err := tegoruntime.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteLockInfo([]byte((tegoruntime.LockInfo{PID: os.Getpid(), StartBootNS: start}).String())); err != nil {
		t.Fatal(err)
	}
	broker, err := ask.New(dir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Second,
		Authorize: func(ask.Peer) error { return errors.New("inside a run") }, Emit: func(ask.Event) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	for _, c := range []struct {
		name, askID string
		approve     bool
	}{{"ask", "", false}, {"approve", "q-" + strings.Repeat("0", 32), true}} {
		var out, errs bytes.Buffer
		code := askAt(t.Context(), c.name, id, dir, c.askID, c.approve, false, false, "", &out, &errs)
		if code != identity.ExitError || !strings.Contains(errs.String(), "unauthorized peer: the run's broker serves only its owner or root") ||
			!strings.Contains(errs.String(), "still pending") {
			t.Errorf("tego %s refused: exit %d, said %q", c.name, code, errs.String())
		}
	}
}
