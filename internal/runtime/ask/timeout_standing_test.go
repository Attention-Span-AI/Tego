// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Under ask.on_timeout: refuse_always (Options.TimeoutStands) an ask nobody answers refuses its operation, and every
// later request for the same operation, rule and target is refused at once, citing the timed-out ask: an agent that
// retries is no longer held for the whole timeout each time (an agent that retried five times was held 15.2 s of a
// 16 s run). Each refusal is its own ask and answer pair, reason ask-timeout, never ask-denied: nobody denied it.
func TestTimeoutStandsRefusesLaterIdenticalRequestsAtOnce(t *testing.T) {
	rec := &recorder{}
	const timeout = 200 * time.Millisecond
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = timeout; o.TimeoutStands = true })
	first, err := b.Request(context.Background(), testRequest())
	if err != nil || first.Approved || first.Reason != ReasonTimeout || first.By != "timeout always" || !first.Always {
		t.Fatalf("the timed-out ask = %+v, %v; want ask-timeout by \"timeout always\"", first, err)
	}
	for i := 0; i < 3; i++ {
		start := time.Now()
		d, err := b.Request(context.Background(), testRequest())
		if err != nil || d.Approved || d.Reason != ReasonTimeout || d.By != "standing:"+first.AskID || !d.Always {
			t.Fatalf("retry %d = %+v, %v; want ask-timeout by standing:%s", i, d, err, first.AskID)
		}
		if held := time.Since(start); held >= timeout {
			t.Fatalf("retry %d was held %v", i, held)
		}
	}
	if pendingCount(t, dir) != 0 {
		t.Fatal("a standing refusal was held")
	}
	ev := rec.snapshot()
	if len(ev) != 8 || ev[1].Kind != "answer" || ev[1].Decision.By != "timeout always" {
		t.Fatalf("ledger = %+v; want the timed-out pair, then three pairs citing it", ev)
	}
	for i := 2; i < 8; i += 2 {
		if ev[i].Kind != "ask" || ev[i+1].Kind != "answer" || ev[i+1].Decision.By != "standing:"+first.AskID || ev[i+1].Decision.Reason != ReasonTimeout {
			t.Fatalf("line %d: %+v", i, ev[i:i+2])
		}
	}
	// Another target is held as before.
	other := testRequest()
	other.Target = "127.0.0.1:444"
	ch := requestAsync(b, other)
	if held := waitAsk(t, dir); held.Target != other.Target {
		t.Fatalf("held %+v", held)
	}
	decisionWithin(t, ch, 2*time.Second)
}

// The default, ask.on_timeout: refuse, is what it always was: a retry is held again for the whole timeout.
func TestTimeoutRefusesOnceByDefault(t *testing.T) {
	const timeout = 100 * time.Millisecond
	b, _ := testBroker(t, func(o *Options) { o.Timeout = timeout })
	for i := 0; i < 2; i++ {
		start := time.Now()
		d, err := b.Request(context.Background(), testRequest())
		if err != nil || d.Approved || d.Reason != ReasonTimeout || d.By != "timeout" || d.Always {
			t.Fatalf("try %d = %+v, %v", i, d, err)
		}
		if held := time.Since(start); held < timeout {
			t.Fatalf("try %d was held only %v: a timeout stood without refuse_always", i, held)
		}
	}
}

// A request that can never be remembered (a content-bound hold, a scored or gate-raised ask) refuses once on a
// timeout under refuse_always too: its approval would have been bound to the bytes or score the person saw.
func TestTimeoutDoesNotStandForWhatCannotBeRemembered(t *testing.T) {
	score := 70
	for name, mutate := range map[string]func(*Request){
		"a request hold":     func(r *Request) { r.Hold = "request" },
		"a first_write hold": func(r *Request) { r.Hold = "first_write" },
		"a scored request":   func(r *Request) { r.Score = &score },
		"a gate-raised ask":  func(r *Request) { r.GateRule = "gate.exec" },
	} {
		t.Run(name, func(t *testing.T) {
			// 300 ms, not 50: the second request is visible to waitAsk only until it times out, and a raced poll on a
			// busy runner missed a 50 ms window (GitHub's race job, 2026-11-02).
			b, dir := testBroker(t, func(o *Options) { o.Timeout = 300 * time.Millisecond; o.TimeoutStands = true })
			req := testRequest()
			mutate(&req)
			d, err := b.Request(context.Background(), req)
			if err != nil || d.Reason != ReasonTimeout || d.Always || d.By != "timeout" {
				t.Fatalf("the timeout = %+v, %v; want a plain one", d, err)
			}
			again := requestAsync(b, req)
			waitAsk(t, dir) // held again
			decisionWithin(t, again, 2*time.Second)
		})
	}
}

// A timeout never stands over a person's "always" for the same key that is still being recorded: that answer stands,
// and the timeout refuses its own request once (the rule ErrStandingBusy keeps between two "always" answers).
func TestTimeoutDoesNotStandOverAnAlwaysBeingRecorded(t *testing.T) {
	rec := &recorder{}
	const timeout = 300 * time.Millisecond
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = timeout; o.TimeoutStands = true })
	first := requestAsync(b, testRequest())
	firstID := waitAsk(t, dir).AskID
	second := requestAsync(b, testRequest())
	var secondID string
	deadline := time.Now().Add(2 * time.Second)
	for secondID == "" && time.Now().Before(deadline) {
		items, err := ListFor(context.Background(), dir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if it.AskID != firstID {
				secondID = it.AskID
			}
		}
		time.Sleep(time.Millisecond)
	}
	if secondID == "" {
		t.Fatal("the second request was not published")
	}
	// The person's "always" for the first is chosen at once, and its answer line is held until the second's timeout
	// has been recorded.
	secondRecorded := make(chan struct{})
	rec.mu.Lock()
	rec.fail = func(e Event) error {
		switch {
		case e.Kind == "answer" && e.Request.AskID == firstID:
			<-secondRecorded
		case e.Kind == "answer" && e.Request.AskID == secondID:
			defer close(secondRecorded)
		}
		return nil
	}
	rec.mu.Unlock()
	go func() { _, _ = AnswerFor(context.Background(), dir, os.Getpid(), firstID, true, true) }()
	got := decisionWithin(t, second, 2*time.Second)
	if got.Reason != ReasonTimeout || got.Always || got.By != "timeout" {
		t.Fatalf("the second's timeout = %+v; want a plain timeout under the always being recorded", got)
	}
	if d := decisionWithin(t, first, 2*time.Second); !d.Approved || !d.Always {
		t.Fatalf("the always answer = %+v", d)
	}
	if d, err := b.Request(context.Background(), testRequest()); err != nil || !d.Approved || d.By != "standing:"+firstID {
		t.Fatalf("a repeat = %+v, %v; want the person's standing approval", d, err)
	}
}

// While a timeout's standing refusal is being recorded, a person's "always" for the same key is refused as busy and
// the request stays pending; once the timeout's line is out, that waiting request is refused with the standing
// refusal, citing the timed-out ask.
func TestAlwaysIsBusyWhileATimeoutThatStandsIsRecorded(t *testing.T) {
	rec := &recorder{}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 600 * time.Millisecond; o.TimeoutStands = true })
	release := make(chan struct{})
	timedOut := make(chan string, 1)
	rec.mu.Lock()
	rec.fail = func(e Event) error {
		if e.Kind == "answer" && e.Decision.By == "timeout always" {
			timedOut <- e.Request.AskID
			<-release
		}
		return nil
	}
	rec.mu.Unlock()
	first := requestAsync(b, testRequest())
	firstID := waitAsk(t, dir).AskID
	var id string
	select {
	case id = <-timedOut:
	case <-time.After(2 * time.Second):
		t.Fatal("the first request did not time out")
	}
	if id != firstID {
		t.Fatalf("timed out %s, want %s", id, firstID)
	}
	// The first's timeout is chosen and its line is being written; a second request for the key is held meanwhile
	// (its ask is published, since nothing stands yet), and a person's always for it is busy.
	second := requestAsync(b, testRequest())
	secondID := ""
	for deadline := time.Now().Add(2 * time.Second); secondID == "" && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		items, err := ListFor(context.Background(), dir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if it.AskID != firstID {
				secondID = it.AskID
			}
		}
	}
	if secondID == "" {
		t.Fatal("the second request was not published")
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), secondID, true, true); err == nil || !strings.Contains(err.Error(), "being recorded") {
		t.Fatalf("an always while the timeout's standing refusal is recorded = %v; want busy", err)
	}
	close(release)
	if d := decisionWithin(t, first, 2*time.Second); d.Reason != ReasonTimeout || !d.Always {
		t.Fatalf("the first = %+v", d)
	}
	if d := decisionWithin(t, second, 2*time.Second); d.Approved || d.Reason != ReasonTimeout || d.By != "standing:"+firstID {
		t.Fatalf("the waiting second = %+v; want refused by standing:%s", d, firstID)
	}
}

// fillStanding puts n standing answers into b, timeouts' when timedOut, for targets no test request uses.
func fillStanding(b *Broker, n int, timedOut bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := 0; i < n; i++ {
		s := standing{askID: "q-fill"}
		if timedOut {
			s.reason = ReasonTimeout
		}
		b.standing[standingKey{op: "connect", rule: "net.ask[0]", target: fmt.Sprintf("10.8.%d.%d:1", i/200, i%200)}] = s
	}
}

// A timeout's answer line says "timeout always" only for a refusal that stands: the slot is reserved when
// the timeout is chosen, so a second timeout that would take the last slot while the first's line is being written
// refuses once, plainly, instead of the first's line saying "always" for a refusal that then stood for nothing and a
// retry of it being held again. The agent alone controls every input here (distinct targets nobody answers).
func TestATimeoutSaysAlwaysOnlyWhenItStands(t *testing.T) {
	rec := &recorder{}
	reqA, reqB := testRequest(), testRequest()
	reqB.Target = "127.0.0.2:443"
	release, aWriting := make(chan struct{}), make(chan struct{})
	rec.fail = func(e Event) error {
		if e.Kind == "answer" && e.Request.Target == reqA.Target && strings.HasPrefix(e.Decision.By, "timeout") {
			close(aWriting)
			<-release
		}
		return nil
	}
	const timeout = 20 * time.Millisecond
	b, _ := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = timeout; o.TimeoutStands = true })
	fillStanding(b, MaxTimeoutStanding-1, true)
	chA := requestAsync(b, reqA)
	<-aWriting
	// A's timeout is chosen and holds the last slot while its line is written: B's timeout cannot stand.
	gotB := decisionWithin(t, requestAsync(b, reqB), 2*time.Second)
	if gotB.Reason != ReasonTimeout || gotB.Always || gotB.By != "timeout" {
		t.Fatalf("B's timeout = %+v; want a plain timeout, the last slot being A's", gotB)
	}
	close(release)
	gotA := decisionWithin(t, chA, 2*time.Second)
	if gotA.Reason != ReasonTimeout || !gotA.Always || gotA.By != "timeout always" {
		t.Fatalf("A's timeout = %+v; want it to stand", gotA)
	}
	for _, e := range rec.snapshot() {
		if e.Kind == "answer" && e.Request.Target == reqB.Target && e.Decision.By != "timeout" {
			t.Fatalf("B's answer line = %+v; want by timeout", e.Decision)
		}
	}
	start := time.Now()
	d, err := b.Request(context.Background(), reqA)
	if err != nil || d.By != "standing:"+gotA.AskID || d.Reason != ReasonTimeout {
		t.Fatalf("a retry of A = %+v, %v; want refused by standing:%s", d, err, gotA.AskID)
	}
	if held := time.Since(start); held >= timeout {
		t.Fatalf("a retry of A was held %v", held)
	}
	b.mu.Lock()
	n := len(b.standing)
	b.mu.Unlock()
	if n != MaxTimeoutStanding {
		t.Fatalf("%d standing answers, want %d", n, MaxTimeoutStanding)
	}
}

// Timeouts never use up the standing answers a person can give: refusals timeouts leave are bounded by
// MaxTimeoutStanding apart from MaxStanding, so with every timeout slot taken a person's --always still stands, and
// past it a timeout refuses once; and with every person's slot taken a timeout still stands.
func TestTimeoutsDoNotUseUpAPersonsStandingAnswers(t *testing.T) {
	t.Run("timeouts full", func(t *testing.T) {
		b, dir := testBroker(t, func(o *Options) { o.Timeout = 300 * time.Millisecond; o.TimeoutStands = true })
		fillStanding(b, MaxTimeoutStanding, true)
		ch := requestAsync(b, testRequest())
		id := waitAsk(t, dir).AskID
		got, err := AnswerFor(context.Background(), dir, os.Getpid(), id, false, true)
		if err != nil || got.Approved || !got.Always {
			t.Fatalf("a person's deny --always with every timeout slot taken = %+v, %v; want it to stand", got, err)
		}
		decisionWithin(t, ch, 2*time.Second)
		other := testRequest()
		other.Target = "127.0.0.3:443"
		if d, err := b.Request(context.Background(), other); err != nil || d.Always || d.By != "timeout" {
			t.Fatalf("a timeout past MaxTimeoutStanding = %+v, %v; want it to refuse once", d, err)
		}
	})
	t.Run("people full", func(t *testing.T) {
		b, _ := testBroker(t, func(o *Options) { o.Timeout = 20 * time.Millisecond; o.TimeoutStands = true })
		fillStanding(b, MaxStanding, false)
		if d, err := b.Request(context.Background(), testRequest()); err != nil || !d.Always || d.By != "timeout always" {
			t.Fatalf("a timeout with every person's slot taken = %+v, %v; want it to stand", d, err)
		}
	})
}

// An answer line that says " always" is what stands, even when the request's owner is cancelled between that line
// and the install (a held thread killed as its timeout or its person's answer was being written): the cancellation
// refuses that one request's operation, and a later identical request finds the recorded answer standing. Before,
// the post-line cancellation replaced the decision and nothing was installed, so the ledger's "timeout always" or
// "... always" named a standing answer that never stood, and a retry was held again.
func TestAnAlwaysLineStandsWhenItsOwnerIsCancelledAfterIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(t *testing.T, dir string) // nil: nobody answers and the ask times out
		reason string
	}{
		{"a timeout under refuse_always", nil, ReasonTimeout},
		{"a person's approve --always", func(t *testing.T, dir string) {
			d, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true)
			if err != nil || d.Approved || !d.Always || d.Reason != ReasonUnavailable {
				t.Errorf("the person's answer came back %+v, %v; want refused for this request and standing", d, err)
			}
		}, ""},
		{"a person's deny --always", func(t *testing.T, dir string) {
			if d, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, false, true); err != nil || !d.Always {
				t.Errorf("the person's answer came back %+v, %v; want standing", d, err)
			}
		}, ReasonDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rec := &recorder{}
			rec.fail = func(e Event) error {
				if e.Kind == "answer" && strings.HasSuffix(e.Decision.By, " always") {
					cancel() // the owner goes away once the line is accepted, before the install
				}
				return nil
			}
			timeout := 30 * time.Second
			if tc.answer == nil {
				timeout = 50 * time.Millisecond
			}
			b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = timeout; o.TimeoutStands = true })
			done := make(chan Decision, 1)
			go func() { d, _ := b.Request(ctx, testRequest()); done <- d }()
			if tc.answer != nil {
				tc.answer(t, dir)
			}
			first := decisionWithin(t, done, 2*time.Second)
			if first.Approved || first.By != "cancelled" || !first.Always {
				t.Fatalf("the cancelled request = %+v; want refused by cancelled, its answer standing", first)
			}
			ev := rec.snapshot()
			if len(ev) != 2 || !strings.HasSuffix(ev[1].Decision.By, " always") {
				t.Fatalf("ledger = %+v", ev)
			}
			again, err := b.Request(context.Background(), testRequest())
			if err != nil || again.By != "standing:"+first.AskID || !again.Always || again.Reason != tc.reason || again.Approved != (tc.reason == "") {
				t.Fatalf("the next identical request = %+v, %v; want it answered by standing:%s", again, err, first.AskID)
			}
		})
	}
}
