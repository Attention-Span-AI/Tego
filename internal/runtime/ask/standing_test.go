// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder collects the events a broker emits, so a test reads the ledger lines a run would write.
type recorder struct {
	mu     sync.Mutex
	events []Event
	fail   func(Event) error
}

func (r *recorder) emit(e Event) error {
	r.mu.Lock()
	fail := r.fail
	r.mu.Unlock()
	if fail != nil { // called outside the lock: a test's hook may wait for another event
		if err := fail(e); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	return nil
}

func (r *recorder) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

func requestAsync(b *Broker, req Request) <-chan Decision {
	ch := make(chan Decision, 1)
	go func() {
		d, _ := b.Request(context.Background(), req)
		ch <- d
	}()
	return ch
}

func decisionWithin(t *testing.T, ch <-chan Decision, d time.Duration) Decision {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(d):
		t.Fatal("no decision in time")
		return Decision{}
	}
}

func pendingCount(t *testing.T, dir string) int {
	t.Helper()
	items, err := ListFor(context.Background(), dir, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return len(items)
}

// Approving "always" answers the held request and every later request for the same operation, rule and target
// without holding it, and the later one leaves the same ask and answer pair in the ledger, by "standing:<id>".
func TestAlwaysAllowAnswersLaterIdenticalRequestsWithoutHolding(t *testing.T) {
	rec := &recorder{}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	id := waitAsk(t, dir).AskID
	answer, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, true)
	if err != nil || !answer.Approved || !answer.Always || !strings.HasSuffix(answer.By, " always") {
		t.Fatalf("the always answer = %+v, %v", answer, err)
	}
	if got := decisionWithin(t, first, 2*time.Second); !got.Approved {
		t.Fatalf("the held request was not approved: %+v", got)
	}

	start := time.Now()
	d, err := b.Request(context.Background(), testRequest())
	if err != nil || !d.Approved || !d.Always || d.By != "standing:"+id || d.AfterS > 1 {
		t.Fatalf("the repeat = %+v, %v; want an immediate allow by standing:%s", d, err, id)
	}
	if time.Since(start) > time.Second || pendingCount(t, dir) != 0 {
		t.Fatalf("the repeat was held (%v, %d pending)", time.Since(start), pendingCount(t, dir))
	}
	// Four lines: the held request's ask and answer, then the repeat's ask and answer, never a silent grant.
	ev := rec.snapshot()
	if len(ev) != 4 || ev[0].Kind != "ask" || ev[1].Kind != "answer" || ev[2].Kind != "ask" || ev[3].Kind != "answer" {
		t.Fatalf("ledger events = %+v", ev)
	}
	if ev[3].Decision.By != "standing:"+id || !ev[3].Decision.Approved || ev[2].Request.AskID != ev[3].Request.AskID || ev[2].Request.AskID == id {
		t.Fatalf("the repeat's answer line does not name the answer behind it, or does not pair with its own ask: %+v", ev[2:])
	}
}

// "Deny always" refuses later identical requests at once, so an agent that retries a refused operation does not
// hold the run, and each refusal is a recorded ask-denied answer.
func TestAlwaysDenyRefusesLaterIdenticalRequests(t *testing.T) {
	rec := &recorder{}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	id := waitAsk(t, dir).AskID
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, false, true); err != nil {
		t.Fatal(err)
	}
	if got := decisionWithin(t, first, 2*time.Second); got.Approved {
		t.Fatalf("the held request was approved: %+v", got)
	}
	for i := 0; i < 3; i++ {
		d, err := b.Request(context.Background(), testRequest())
		if err != nil || d.Approved || d.Reason != ReasonDenied || d.By != "standing:"+id || !d.Always {
			t.Fatalf("repeat %d = %+v, %v; want a standing refusal", i, d, err)
		}
	}
	if pendingCount(t, dir) != 0 {
		t.Fatal("a standing refusal was held")
	}
	if n := len(rec.snapshot()); n != 8 { // the held pair, then three repeats of two lines
		t.Fatalf("ledger lines = %d, want 8", n)
	}
}

// A standing decision matches the operation, the rule and the exact target, and nothing more: a request that
// differs in any one is held, so "always" never reaches what the human did not see.
func TestStandingMatchesExactlyTheOperationRuleAndTarget(t *testing.T) {
	b, dir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, first, 2*time.Second)

	for name, mutate := range map[string]func(*Request){
		"another target":    func(r *Request) { r.Target = "127.0.0.1:444" },
		"another rule":      func(r *Request) { r.Rule = "net.ask[1]" },
		"another operation": func(r *Request) { r.Op = "connect6" },
		"a prefix of it":    func(r *Request) { r.Target = "127.0.0.1:44" },
	} {
		req := testRequest()
		mutate(&req)
		ch := requestAsync(b, req)
		held := waitAsk(t, dir)
		if held.Target != req.Target || held.Rule != req.Rule || held.Op != req.Op {
			t.Fatalf("%s: held %+v", name, held)
		}
		if _, err := AnswerFor(context.Background(), dir, os.Getpid(), held.AskID, false, false); err != nil {
			t.Fatal(err)
		}
		if got := decisionWithin(t, ch, 2*time.Second); got.Approved || got.Always {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	// The request the standing decision was made for is still answered at once.
	if d, err := b.Request(context.Background(), testRequest()); err != nil || !d.Approved || !d.Always {
		t.Fatalf("the original = %+v, %v", d, err)
	}
}

// Content-bound and scored holds are never remembered: their approval was for the bytes or the score the human
// saw. The "always" is refused, the request stays pending, and a plain answer still works.
func TestContentBoundAndScoredHoldsAreNeverRemembered(t *testing.T) {
	score := 70
	for name, mutate := range map[string]func(*Request){
		"a request hold":     func(r *Request) { r.Hold = "request" },
		"a first_write hold": func(r *Request) { r.Hold = "first_write" },
		"a scored request":   func(r *Request) { r.Score = &score },
		"a gate-raised ask":  func(r *Request) { r.GateRule = "gate.exec" },
	} {
		t.Run(name, func(t *testing.T) {
			b, dir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
			req := testRequest()
			mutate(&req)
			ch := requestAsync(b, req)
			id := waitAsk(t, dir).AskID
			if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, true); !errors.Is(err, ErrNotRememberable) {
				t.Fatalf("always on %s = %v, want ErrNotRememberable", name, err)
			}
			if pendingCount(t, dir) != 1 {
				t.Fatal("the refused always consumed the ask")
			}
			if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, false); err != nil {
				t.Fatalf("the plain answer failed: %v", err)
			}
			if got := decisionWithin(t, ch, 2*time.Second); !got.Approved || got.Always {
				t.Fatalf("%+v", got)
			}
			// And the next identical request is held again.
			again := requestAsync(b, req)
			next := waitAsk(t, dir)
			if next.AskID == id {
				t.Fatal("the same ask came back")
			}
			if _, err := AnswerFor(context.Background(), dir, os.Getpid(), next.AskID, false, false); err != nil {
				t.Fatal(err)
			}
			decisionWithin(t, again, 2*time.Second)
		})
	}
}

// An identical request already held when the human answers "always" gets the same answer, so they are not asked
// again for what they just decided.
func TestAlwaysAnswersIdenticalRequestsAlreadyHeld(t *testing.T) {
	b, dir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
	one, two := requestAsync(b, testRequest()), requestAsync(b, testRequest())
	var ids []string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(ids) < 2 {
		items, err := ListFor(context.Background(), dir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		ids = ids[:0]
		for _, it := range items {
			ids = append(ids, it.AskID)
		}
		time.Sleep(time.Millisecond)
	}
	if len(ids) != 2 {
		t.Fatalf("held = %v, want two", ids)
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), ids[0], false, true); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []<-chan Decision{one, two} {
		if got := decisionWithin(t, ch, 2*time.Second); got.Approved || got.Reason != ReasonDenied {
			t.Fatalf("a held duplicate = %+v", got)
		}
	}
	if pendingCount(t, dir) != 0 {
		t.Fatal("a duplicate stayed pending")
	}
}

// The run's standing decisions are bounded. At the bound a new "always" is refused and the ask stays pending;
// a decision already standing can still be replaced.
func TestStandingDecisionsAreBounded(t *testing.T) {
	b, dir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
	b.mu.Lock()
	for i := 0; i < MaxStanding; i++ {
		b.standing[standingKey{op: "connect", rule: "net.ask[0]", target: "10.0.0." + string(rune('a'+i%26)) + strings.Repeat("x", i)}] = standing{askID: "q-fill"}
	}
	b.mu.Unlock()
	ch := requestAsync(b, testRequest())
	id := waitAsk(t, dir).AskID
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, true); !errors.Is(err, ErrStandingFull) {
		t.Fatalf("always at the bound = %v, want ErrStandingFull", err)
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, false); err != nil {
		t.Fatal(err)
	}
	if got := decisionWithin(t, ch, 2*time.Second); !got.Approved || got.Always {
		t.Fatalf("%+v", got)
	}
}

// The ledger decides: if it refuses either line of a standing decision, the operation is refused, as for a
// held one. A standing allow never turns into an unrecorded grant.
func TestStandingDecisionFailsClosedWhenTheLedgerRefuses(t *testing.T) {
	rec := &recorder{}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, first, 2*time.Second)

	for _, kind := range []string{"ask", "answer"} {
		rec.mu.Lock()
		rec.fail = func(e Event) error {
			if e.Kind == kind {
				return errors.New("ledger full")
			}
			return nil
		}
		rec.mu.Unlock()
		d, err := b.Request(context.Background(), testRequest())
		if err == nil || d.Approved {
			t.Fatalf("a ledger that refuses the %s line still allowed: %+v, %v", kind, d, err)
		}
	}
}

// A closed broker holds no standing decisions to apply: its requests are refused as unavailable.
func TestStandingDecisionsDieWithTheBroker(t *testing.T) {
	b, dir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, first, 2*time.Second)
	b.shutdown()
	if d, err := b.Request(context.Background(), testRequest()); err == nil || d.Approved {
		t.Fatalf("a closed broker answered from memory: %+v, %v", d, err)
	}
}

// Only an answer carries "remember", once, and it is a boolean.
func TestDecodeCommandRemember(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	id := "q-" + strings.Repeat("a", 32)
	ok := []string{
		`{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"remember":true}`,
		`{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":false,"remember":false}`,
		`{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true}`,
	}
	for _, c := range ok {
		if _, err := decodeCommand([]byte(c)); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	bad := []string{
		`{"action":"list","nonce":"` + nonce + `","remember":true}`,
		`{"action":"detail","nonce":"` + nonce + `","ask_id":"` + id + `","remember":true}`,
		`{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"remember":true,"remember":false}`,
		`{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"remember":null}`,
		`{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"remember":"yes"}`,
	}
	for _, c := range bad {
		if _, err := decodeCommand([]byte(c)); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: err = %v, want ErrProtocol", c, err)
		}
	}
}

// A request registered while an "always" answer is given, with its ask line still being written, is answered by
// it as well: it is never held for a person who has just decided.
func TestAlwaysAnswersARequestRegisteredButNotYetPublished(t *testing.T) {
	var asks int
	var mu sync.Mutex
	release := make(chan struct{})
	rec := &recorder{}
	rec.fail = func(e Event) error {
		if e.Kind != "ask" {
			return nil
		}
		mu.Lock()
		asks++
		n := asks
		mu.Unlock()
		if n == 2 { // the second request's ask line waits until the answer has been given
			<-release
		}
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	id := waitAsk(t, dir).AskID
	second := requestAsync(b, testRequest())
	deadline := time.Now().Add(2 * time.Second)
	for {
		b.mu.Lock()
		n := len(b.pending)
		b.mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second request was not registered")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, true); err != nil {
		t.Fatal(err)
	}
	close(release)
	decisionWithin(t, first, 2*time.Second)
	got := decisionWithin(t, second, 2*time.Second) // held for 30 s without the fix
	if !got.Approved || !got.Always || got.By != "standing:"+id {
		t.Fatalf("the unpublished request = %+v, want the standing allow", got)
	}
	if pendingCount(t, dir) != 0 {
		t.Fatal("a request stayed pending")
	}
}

// An "always" answer whose request is cancelled while the answer line is written refuses that request, and stands:
// the person is not told "approved" for something that was refused, but their recorded "... always" line is what
// later identical requests are answered from (before, nothing was installed,
// and the ledger's "always" line named a standing answer that never stood).
func TestAnAlwaysAnswerThatIsCancelledAfterItsLineStillStands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &recorder{}
	rec.fail = func(e Event) error {
		if e.Kind == "answer" && strings.HasSuffix(e.Decision.By, " always") {
			cancel() // the held operation's thread dies while the answer line is being written
		}
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	first := make(chan Decision, 1)
	go func() { d, _ := b.Request(ctx, testRequest()); first <- d }()
	id := waitAsk(t, dir).AskID
	got, err := AnswerFor(context.Background(), dir, os.Getpid(), id, true, true)
	if err != nil || got.Approved || !got.Always || got.Reason != ReasonUnavailable {
		t.Fatalf("a cancelled always answer = %+v, %v; want the cancellation, and the answer standing", got, err)
	}
	if d := decisionWithin(t, first, 2*time.Second); d.Approved {
		t.Fatalf("the cancelled request was approved: %+v", d)
	}
	// The next identical request is answered from the recorded line, without a person.
	if d, err := b.Request(context.Background(), testRequest()); err != nil || !d.Approved || d.By != "standing:"+id {
		t.Fatalf("the next identical request = %+v, %v; want the standing approval by standing:%s", d, err, id)
	}
}

// A standing answer is an ask line then an answer line, so it is an open ask in the ledger for a moment, and the
// ledger's reader refuses more than the cap of them at once. The broker keeps that invariant: with the cap's worth
// of held requests, a request a standing answer covers is refused rather than written as one open ask too many.
func TestStandingAnswersCountAgainstTheOpenAskCap(t *testing.T) {
	var mu sync.Mutex
	open, most := 0, 0
	emit := func(e Event) error {
		mu.Lock()
		defer mu.Unlock()
		switch e.Kind {
		case "ask":
			if open++; open > most {
				most = open
			}
		case "answer":
			open--
		}
		return nil
	}
	const cap = 3
	b, dir := testBroker(t, func(o *Options) { o.Emit = emit; o.MaxPending = cap; o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, first, 2*time.Second)

	var held []<-chan Decision
	for i := 0; i < cap; i++ {
		r := testRequest()
		r.Target = fmt.Sprintf("10.0.0.%d:443", i)
		held = append(held, requestAsync(b, r))
	}
	deadline := time.Now().Add(2 * time.Second)
	for pendingCount(t, dir) != cap {
		if time.Now().After(deadline) {
			t.Fatal("the held requests were not published")
		}
		time.Sleep(time.Millisecond)
	}
	if d, err := b.Request(context.Background(), testRequest()); !errors.Is(err, ErrUnavailable) || d.Approved {
		t.Fatalf("a standing request at the cap = %+v, %v; want it refused as unavailable", d, err)
	}
	// One held request is answered: a slot frees and the standing answer applies again.
	items, err := ListFor(context.Background(), dir, os.Getpid())
	if err != nil || len(items) != cap {
		t.Fatalf("held = %v, %v", items, err)
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), items[0].AskID, false, false); err != nil {
		t.Fatal(err)
	}
	if d, err := b.Request(context.Background(), testRequest()); err != nil || !d.Approved || !d.Always {
		t.Fatalf("a standing request with a free slot = %+v, %v", d, err)
	}
	for _, ch := range held {
		_ = ch // the rest are released by the broker's cleanup
	}
	mu.Lock()
	defer mu.Unlock()
	if most > cap {
		t.Fatalf("%d asks were open in the ledger at once, cap %d", most, cap)
	}
}

// A line that cites a human answer comes after it in the ledger: an identical request already held is answered
// only once the human's own line is recorded, so the reference never precedes its source, and a human line the
// ledger refuses grants nothing to anyone.
func TestAStandingAnswerLineFollowsTheHumanLineItCites(t *testing.T) {
	release, blocked := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var order []string
	var once sync.Once
	emit := func(e Event) error {
		if e.Kind != "answer" {
			return nil
		}
		if strings.HasSuffix(e.Decision.By, " always") {
			once.Do(func() { close(blocked) })
			<-release // the human's line is slow to reach the ledger
		}
		mu.Lock()
		order = append(order, e.Decision.By)
		mu.Unlock()
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = emit; o.Timeout = 30 * time.Second })
	one, two := requestAsync(b, testRequest()), requestAsync(b, testRequest())
	ids := heldAskIDs(t, dir, 2)
	done := make(chan struct{})
	go func() {
		_, _ = AnswerFor(context.Background(), dir, os.Getpid(), ids[0], true, true)
		close(done)
	}()
	<-blocked
	// The human's answer is chosen and its line is not written. The duplicate must be neither answered nor
	// resolved yet, and nothing may stand yet: whatever cites the human's line has to follow it.
	b.mu.Lock()
	for id, q := range b.pending {
		if id != ids[0] && q.won {
			t.Errorf("the duplicate %s was resolved before the human's line was written", id)
		}
	}
	if n := len(b.standing); n != 0 {
		t.Errorf("%d standing answers stand before the human's line was written", n)
	}
	b.mu.Unlock()
	close(release)
	<-done
	decisionWithin(t, one, 2*time.Second)
	decisionWithin(t, two, 2*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || !strings.HasSuffix(order[0], " always") || !strings.HasPrefix(order[1], "standing:") {
		t.Fatalf("answer lines in ledger order = %q; want the human's, then the one citing it", order)
	}
}

// heldAskIDs waits for n published requests and returns their ask ids.
func heldAskIDs(t *testing.T, dir string, n int) []string {
	t.Helper()
	var ids []string
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		items, err := ListFor(context.Background(), dir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		ids = ids[:0]
		for _, it := range items {
			ids = append(ids, it.AskID)
		}
		if len(ids) == n {
			return ids
		}
	}
	t.Fatalf("held = %v, want %d", ids, n)
	return nil
}

// A broker that closes while a standing answer's line is being written refuses the operation, as for a held one.
func TestAStandingAnswerIsRefusedWhenTheBrokerClosesWhileItsLineIsWritten(t *testing.T) {
	var b *Broker
	var armed atomic.Bool
	rec := &recorder{}
	rec.fail = func(e Event) error {
		if armed.Load() && e.Kind == "answer" {
			b.shutdown()
		}
		return nil
	}
	var dir string
	b, dir = testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	first := requestAsync(b, testRequest())
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, first, 2*time.Second)
	armed.Store(true)
	if d, _ := b.Request(context.Background(), testRequest()); d.Approved {
		t.Fatalf("a standing answer survived the broker closing: %+v", d)
	}
}

// A standing answer between its ask line and its answer line is an open ask: another request arriving then, with the
// rest of the cap held, must not make one more.
func TestAStandingAnswerInFlightCountsAgainstTheOpenAskCap(t *testing.T) {
	const cap = 3
	release := make(chan struct{})
	var mu sync.Mutex
	open, most := 0, 0
	emit := func(e Event) error {
		if e.Kind == "answer" && strings.HasPrefix(e.Decision.By, "standing:") {
			<-release // the standing answer's line is slow: it stays an open ask
		}
		mu.Lock()
		defer mu.Unlock()
		switch e.Kind {
		case "ask":
			if open++; open > most {
				most = open
			}
		case "answer":
			open--
		}
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = emit; o.MaxPending = cap; o.Timeout = 2 * time.Second })
	first := requestAsync(b, testRequest())
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, first, time.Second)

	for i := 0; i < cap-1; i++ { // the cap less one, held
		r := testRequest()
		r.Target = fmt.Sprintf("10.0.0.%d:443", i)
		requestAsync(b, r)
	}
	deadline := time.Now().Add(2 * time.Second)
	for pendingCount(t, dir) != cap-1 {
		if time.Now().After(deadline) {
			t.Fatal("the held requests were not published")
		}
		time.Sleep(time.Millisecond)
	}
	inflight := requestAsync(b, testRequest()) // the standing answer: its ask line is out, its answer line waits
	for {
		mu.Lock()
		n := open
		mu.Unlock()
		if n == cap {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the standing request was not in flight (open asks %d)", n)
		}
		time.Sleep(time.Millisecond)
	}
	r := testRequest()
	r.Target = "10.9.9.9:443"
	if d, err := b.Request(context.Background(), r); !errors.Is(err, ErrUnavailable) || d.Approved {
		t.Fatalf("a request arriving with the cap held and a standing answer in flight = %+v, %v; want it refused", d, err)
	}
	close(release)
	if got := decisionWithin(t, inflight, time.Second); !got.Approved || !got.Always {
		t.Fatalf("the standing answer in flight = %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if most > cap {
		t.Fatalf("%d asks were open in the ledger at once, cap %d", most, cap)
	}
}

// Two "always" answers for one key cannot both stand. While the first is being recorded its duplicates are still
// held, and a second "always" for them is refused (ErrStandingBusy, the request stays pending) instead of being
// accepted and then overwritten by, or overwriting, the first: the person who answered second was told a denial
// stands while an approval did.
func TestTwoAlwaysAnswersForOneKeyCannotBothStand(t *testing.T) {
	release, blocked := make(chan struct{}), make(chan struct{})
	var once sync.Once
	emit := func(e Event) error {
		if e.Kind == "answer" && strings.HasSuffix(e.Decision.By, " always") {
			once.Do(func() { close(blocked) })
			<-release
		}
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = emit; o.Timeout = 30 * time.Second })
	one, two := requestAsync(b, testRequest()), requestAsync(b, testRequest())
	ids := heldAskIDs(t, dir, 2)
	first := make(chan Decision, 1)
	go func() {
		d, _ := AnswerFor(context.Background(), dir, os.Getpid(), ids[0], true, true)
		first <- d
	}()
	<-blocked
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), ids[1], false, true); !errors.Is(err, ErrStandingBusy) {
		t.Fatalf("a second always for the key being recorded = %v, want ErrStandingBusy", err)
	}
	if n := pendingCount(t, dir); n != 1 {
		t.Fatalf("%d requests pending after the refused always, want the one still held", n)
	}
	close(release)
	if got := decisionWithin(t, first, 2*time.Second); !got.Approved || !got.Always {
		t.Fatalf("the first always = %+v", got)
	}
	for _, ch := range []<-chan Decision{one, two} {
		if got := decisionWithin(t, ch, 2*time.Second); !got.Approved || !got.Always {
			t.Fatalf("a request for the key = %+v, want the approval that stands", got)
		}
	}
	if d, err := b.Request(context.Background(), testRequest()); err != nil || !d.Approved || !strings.HasPrefix(d.By, "standing:"+ids[0]) {
		t.Fatalf("a later request = %+v, %v; want the first answer's approval", d, err)
	}
}

// An owner that cancels while a standing answer's lines are written gets a refusal, as a held request would, and
// the ledger line records the cancellation, not a grant, when it is known before the line is written.
func TestAStandingAnswerRefusesWhenItsOwnerCancelsWhileItsLinesAreWritten(t *testing.T) {
	for _, when := range []string{"ask", "answer"} {
		t.Run("cancelled at the "+when+" line", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var armed atomic.Bool
			rec := &recorder{}
			rec.fail = func(e Event) error {
				if armed.Load() && e.Kind == when {
					cancel()
				}
				return nil
			}
			b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
			first := requestAsync(b, testRequest())
			if _, err := AnswerFor(context.Background(), dir, os.Getpid(), waitAsk(t, dir).AskID, true, true); err != nil {
				t.Fatal(err)
			}
			decisionWithin(t, first, 2*time.Second)
			armed.Store(true)
			d, _ := b.Request(ctx, testRequest())
			if d.Approved || d.Always {
				t.Fatalf("a standing approval survived its owner's cancellation: %+v", d)
			}
			events := rec.snapshot()
			last := events[len(events)-1]
			if last.Kind != "answer" {
				t.Fatalf("the ledger's last line is %q, want the answer that closes the ask", last.Kind)
			}
			if when == "ask" && (last.Decision.Approved || last.Decision.By != "cancelled") {
				t.Fatalf("the answer line after a cancellation records %+v, want the cancellation", last.Decision)
			}
		})
	}
}

// A ledger that refuses the human's own "always" line grants nothing and stands for nothing: the answer is not
// recorded, so no later request may cite it, and the next identical request is held for a person again.
func TestALedgerThatRefusesTheHumansAlwaysLineLeavesNothingStanding(t *testing.T) {
	rec := &recorder{}
	rec.fail = func(e Event) error {
		if e.Kind == "answer" && strings.HasSuffix(e.Decision.By, " always") {
			return errors.New("ledger full")
		}
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	first := make(chan Decision, 1)
	go func() { d, _ := b.Request(context.Background(), testRequest()); first <- d }()
	id := waitAsk(t, dir).AskID
	_, _ = AnswerFor(context.Background(), dir, os.Getpid(), id, true, true)
	if d := decisionWithin(t, first, 2*time.Second); d.Approved || d.Always {
		t.Fatalf("an always whose line the ledger refused = %+v", d)
	}
	rec.mu.Lock()
	rec.fail = nil
	rec.mu.Unlock()
	second := requestAsync(b, testRequest())
	held := waitAsk(t, dir) // held again: nothing stands to answer it
	if held.AskID == id {
		t.Fatal("the same ask came back")
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), held.AskID, false, false); err != nil {
		t.Fatal(err)
	}
	if d := decisionWithin(t, second, 2*time.Second); d.Approved {
		t.Fatalf("%+v", d)
	}
}

// The bound on a run's standing answers holds when several "always" answers are chosen before any is installed: an
// "always" chosen and still being recorded reserves its slot, so the one that would be the 257th is refused
// ErrStandingFull at once and its request stays pending, and no answer line says "always" for an answer that stood
// for nothing (the timeout's case, is TestATimeoutSaysAlwaysOnlyWhenItStands).
func TestConcurrentAlwaysAnswersCannotExceedTheStandingBound(t *testing.T) {
	release, blocked := make(chan struct{}), make(chan struct{})
	var once sync.Once
	emit := func(e Event) error {
		if e.Kind == "answer" && strings.HasSuffix(e.Decision.By, " always") {
			first := false
			once.Do(func() { first = true; close(blocked) })
			if first {
				<-release // the first human line waits; the second passes
			}
		}
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = emit; o.Timeout = 30 * time.Second })
	b.mu.Lock()
	for i := 0; i < MaxStanding-1; i++ {
		b.standing[standingKey{op: "connect", rule: "net.ask[0]", target: fmt.Sprintf("10.9.%d.%d:1", i/200, i%200)}] = standing{askID: "q-fill"}
	}
	b.mu.Unlock()
	reqA, reqB := testRequest(), testRequest()
	reqB.Target = "127.0.0.2:443"
	chA, chB := requestAsync(b, reqA), requestAsync(b, reqB)
	ids := heldAskIDs(t, dir, 2)
	byTarget := map[string]string{}
	for _, id := range ids {
		d, err := DetailFor(context.Background(), dir, os.Getpid(), id)
		if err != nil {
			t.Fatal(err)
		}
		byTarget[d.Target] = id
	}
	firstDone := make(chan Decision, 1)
	go func() {
		d, _ := AnswerFor(context.Background(), dir, os.Getpid(), byTarget[reqA.Target], true, true)
		firstDone <- d
	}()
	<-blocked
	// 255 stand and the first, still being recorded, holds the 256th slot: the second always is full, and its request
	// stays pending for an answer given once.
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), byTarget[reqB.Target], true, true); !errors.Is(err, ErrStandingFull) {
		t.Fatalf("the second always = %v; want ErrStandingFull while the first holds the last slot", err)
	}
	gotB, err := AnswerFor(context.Background(), dir, os.Getpid(), byTarget[reqB.Target], true, false)
	if err != nil || !gotB.Approved || gotB.Always {
		t.Fatalf("the second, answered once = %+v, %v", gotB, err)
	}
	close(release)
	gotA := decisionWithin(t, firstDone, 2*time.Second)
	if !gotA.Approved || !gotA.Always {
		t.Fatalf("the first always = %+v; want it to stand as the 256th", gotA)
	}
	decisionWithin(t, chA, 2*time.Second)
	decisionWithin(t, chB, 2*time.Second)
	b.mu.Lock()
	n := len(b.standing)
	b.mu.Unlock()
	if n != MaxStanding {
		t.Fatalf("%d standing answers, want exactly %d", n, MaxStanding)
	}
	// What stood answers a repeat at once; what was answered once is held for a person again.
	if d, err := b.Request(context.Background(), reqA); err != nil || !d.Approved || d.By != "standing:"+byTarget[reqA.Target] {
		t.Fatalf("a repeat of the first = %+v, %v; want its standing approval", d, err)
	}
	again := requestAsync(b, reqB)
	if held := waitAsk(t, dir); held.Target != reqB.Target {
		t.Fatalf("held %+v, want the request answered once", held)
	}
	_ = again
}
