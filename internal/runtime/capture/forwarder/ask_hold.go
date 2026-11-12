// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type requestAskEntry struct {
	ready, done          chan struct{}
	decision             ask.Decision
	err                  error
	dispatched, finished bool
	resolved             bool
	seen                 time.Time
	replay               *askReplay
	// expiry ends a dispatched entry's retry window on time (expire), not at the next ask's sweep.
	expiry *time.Timer
}

// A shared run-level coordinator bounds pending approvals and response replay
// state. Only one handler receives the upstream dispatch ticket for each full
// request identity; a cancelled waiter cannot cancel the shared human wait.
type requestAsks struct {
	mu      sync.Mutex
	table   *agent.RuleTable
	request func(context.Context, ask.Request) (ask.Decision, error)
	ctx     context.Context
	cancel  context.CancelFunc
	closed  bool
	entries map[[32]byte]*requestAskEntry
	wg      sync.WaitGroup
	// ttl is how long a finished entry stays a retry's replay, DefaultRetryTTL (R24); tests shorten it.
	ttl time.Duration
}

func newRequestAsks(rt *agent.RuleTable, request func(context.Context, ask.Request) (ask.Decision, error)) (*requestAsks, error) {
	if rt == nil || rt.AskConfig == nil || rt.AskConfig.Hold != agent.AskHoldRequest || request == nil || rt.AskConfig.MaxPending < 1 || rt.AskConfig.MaxPending > ask.DefaultMaxPending || time.Duration(rt.AskConfig.Timeout) <= 0 {
		return nil, ask.ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &requestAsks{table: rt, request: request, ctx: ctx, cancel: cancel, entries: make(map[[32]byte]*requestAskEntry), ttl: DefaultRetryTTL}, nil
}

func (a *requestAsks) Close() error {
	a.mu.Lock()
	a.closed = true
	a.cancel()
	for _, e := range a.entries {
		if e.expiry != nil {
			e.expiry.Stop()
		}
		if e.replay != nil {
			e.replay.drop()
		}
	}
	a.mu.Unlock()
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("forwarder: request ask workers did not stop")
	}
}

// readProcStat reads one /proc/<pid>/stat file; a test stands a sequence of lines in for it.
var readProcStat = func(pid int) ([]byte, error) { return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat") }

// requestAskIdentity is the coalescing key of a held request: the sender (pid and birth), the method, the declared
// endpoint, the route the request chose ("" for an endpoint without routes, direct for its own upstream), the target,
// the body and every semantic header. The route is in it so a repeat that arrives after a person moved the endpoint
// gets an approval of its own, whose card shows where it goes, rather than joining one whose card showed another
// destination (ADR 0127 §4).
func requestAskIdentity(r *http.Request, pid int, authority, route string, body []byte) ([32]byte, error) {
	// Retain the sender's birth in the key, so a reused numeric PID cannot
	// inherit a cached approval from an earlier process of the same run.
	// A released line (process group -1) is read again: a live process is its own line, a gone one ENOENT.
	st, err := proc.ReadParsedStat(func() ([]byte, error) { return readProcStat(pid) })
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	var birth [16]byte
	binary.LittleEndian.PutUint64(birth[:], uint64(pid))
	binary.LittleEndian.PutUint64(birth[8:], st.StartTicks)
	h.Write(birth[:])
	for _, s := range []string{r.Method, authority, route, requestTarget(r)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	sum := sha256.Sum256(body)
	h.Write(sum[:])
	// Hash every semantic header and every duplicate value. Credentials are
	// never retained in the key or ask metadata; retry-count changes alone do
	// not create another upstream dispatch.
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		// Connection nominates other headers for removal during forwarding. It
		// therefore changes effective credentials and must distinguish approvals.
		if strings.EqualFold(k, RetryHeader) || strings.EqualFold(k, "Expect") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(strings.ToLower(k)))
		h.Write([]byte{0})
		for _, v := range r.Header[k] {
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
		h.Write([]byte{0})
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key, nil
}

func (a *requestAsks) entry(key [32]byte, req ask.Request) (*requestAskEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ask.ErrUnavailable
	}
	// Never evict an outstanding human wait or upstream operation. Finished
	// entries are a bounded replay cache, not a permanent idempotency store.
	var oldestKey [32]byte
	var oldest *requestAskEntry
	for k, e := range a.entries {
		if !e.finished && !(e.resolved && !e.dispatched && time.Since(e.seen) > a.ttl) {
			continue
		}
		if time.Since(e.seen) > a.ttl {
			if e.replay != nil {
				e.replay.drop()
			}
			delete(a.entries, k)
			continue
		}
		if oldest == nil || e.seen.Before(oldest.seen) {
			oldestKey, oldest = k, e
		}
	}
	if e := a.entries[key]; e != nil {
		return e, nil
	}
	if len(a.entries) >= a.table.AskConfig.MaxPending {
		if oldest == nil {
			return nil, ask.ErrUnavailable
		}
		if oldest.replay != nil {
			oldest.replay.drop()
		}
		delete(a.entries, oldestKey)
	}
	e := &requestAskEntry{ready: make(chan struct{}), done: make(chan struct{}), seen: time.Now()}
	a.entries[key] = e
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ctx, cancel := context.WithTimeout(a.ctx, time.Duration(a.table.AskConfig.Timeout))
		defer cancel()
		d, err := a.request(ctx, req)
		if cause := ctx.Err(); cause != nil && err == nil {
			d.Approved = false
			err = cause
		}
		a.mu.Lock()
		e.decision, e.err, e.resolved = d, err, true
		e.seen = time.Now()
		if err != nil || !d.Approved {
			e.finished = true
			e.seen = time.Now()
			close(e.done)
		}
		close(e.ready)
		a.mu.Unlock()
	}()
	return e, nil
}

// expire ends a dispatched entry's retry window (R24): its replay goes back to the run's shared capture
// budget and its slot to max_pending. The sweep in entry() did this only when another request asked, so a
// run that asked nothing more kept every approved response pinned until it ended, and a later body the
// budget could no longer hold was refused 413 before it reached that sweep. An entry already swept, evicted
// or replaced is left alone.
func (a *requestAsks) expire(key [32]byte, e *requestAskEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.entries[key] != e {
		return
	}
	if e.replay != nil {
		e.replay.drop()
	}
	delete(a.entries, key)
}

func (l *Listener) requestAskRule() (string, bool) {
	a := l.opts.askRequests
	if a == nil {
		return "", false
	}
	port := l.model.Port
	if port == 0 {
		port = 443
	}
	host := agent.CanonicalHost(l.model.Host)
	match := func(r agent.NetRule) bool {
		if r.Port != port && r.Port != 0 {
			return false
		}
		if !agent.ProtocolMatches(r.Proto, agent.ProtoTCP) {
			return false
		}
		if agent.CanonicalHost(r.Host) == host {
			return true
		}
		ip, ipErr := netip.ParseAddr(host)
		if ipErr == nil && r.CIDR != nil && r.CIDR.Contains(ip.Unmap()) {
			return true
		}
		for _, ip := range r.IPs {
			if ip.String() == host {
				return true
			}
		}
		return false
	}
	for _, r := range a.table.Net {
		if match(r) {
			return "", false
		}
	}
	for _, r := range a.table.NetAsk {
		if match(r) {
			return r.RuleName(), true
		}
	}
	return "", false
}

// askTarget is the destination a person approving a request is shown: the declared endpoint, and, when the endpoint
// is on a route other than its own, that route and its backend (ADR 0127), so the decision is made on where the request
// will go. The coalescing key carries the route too (requestAskIdentity), so a card never stands for a request that goes
// elsewhere.
func askTarget(authority string, via *routeChoice) string {
	if via == nil || via.route.IsDirect() {
		return authority
	}
	return authority + " via " + via.route.Name + " (" + via.route.Authority() + ")"
}

func (l *Listener) askExchange(w http.ResponseWriter, r *http.Request, pid int, x *exchange) (http.ResponseWriter, func(), bool) {
	rule, matched := l.requestAskRule()
	if !matched {
		return w, func() {}, true
	}
	a := l.opts.askRequests
	discard := func() {
		l.budget.give(x.held)
		x.held = 0
		if x.guard != nil {
			x.guard.retire()
		}
	}
	refuse := func(reason string, status int) {
		discard()
		closeHTTPUpload(w, r)
		ev := l.event(record.KindNet, l.opts.Clock.Now(), l.opts.Clock.Mono())
		ev.PID, ev.TID, ev.Rule, ev.Verdict, ev.Reason = pid, pid, rule, record.VerdictRefused, record.Reason(reason)
		port := l.model.Port
		if port == 0 {
			port = 443
		}
		authority := httppolicy.Authority(l.model.Host, port)
		_ = ev.SetPayload(record.NetPayload{Op: "http_request", Proto: "http", Dst: authority, HTTPAuthority: authority, Method: r.Method, Path: r.URL.EscapedPath()})
		l.emit(ev)
		http.Error(w, "HTTP request approval refused: "+reason, status)
	}
	if x.truncated || x.rest != nil {
		refuse(ask.ReasonUnavailable, http.StatusRequestEntityTooLarge)
		return w, func() {}, false
	}
	port := l.model.Port
	if port == 0 {
		port = 443
	}
	authority := httppolicy.Authority(l.model.Host, port)
	key, err := requestAskIdentity(r, pid, authority, routeName(x.via), x.body)
	if err != nil {
		refuse(ask.ReasonUnavailable, http.StatusForbidden)
		return w, func() {}, false
	}
	e, err := a.entry(key, ask.Request{Op: "http_request", Target: askTarget(authority, x.via) + " " + r.Method + " " + r.URL.EscapedPath(), Rule: rule, Hold: "request", PID: pid, TID: pid})
	if err != nil {
		refuse(ask.ReasonUnavailable, http.StatusServiceUnavailable)
		return w, func() {}, false
	}
	select {
	case <-e.ready:
	case <-r.Context().Done():
		discard()
		return w, func() {}, false
	case <-a.ctx.Done():
		refuse(ask.ReasonUnavailable, http.StatusForbidden)
		return w, func() {}, false
	}
	a.mu.Lock()
	decision, decisionErr := e.decision, e.err
	if decisionErr != nil || !decision.Approved {
		a.mu.Unlock()
		reason := decision.Reason
		if errors.Is(decisionErr, context.DeadlineExceeded) {
			reason = ask.ReasonTimeout
		} else if decisionErr != nil || reason == "" {
			reason = ask.ReasonUnavailable
		}
		refuse(reason, http.StatusForbidden)
		return w, func() {}, false
	}
	if r.Context().Err() != nil || a.closed {
		a.mu.Unlock()
		discard()
		return w, func() {}, false
	}
	if !e.dispatched {
		e.dispatched = true
		replay := &askReplay{writer: w, body: l.budget.hold(l.opts.MaxBody), valid: true}
		e.replay = replay
		a.mu.Unlock()
		finish := func() {
			p := recover()
			replay.finish(p == nil)
			a.mu.Lock()
			e.finished = true
			e.seen = time.Now()
			close(e.done)
			if !a.closed {
				e.expiry = time.AfterFunc(a.ttl, func() { a.expire(key, e) })
			}
			a.mu.Unlock()
			if p != nil {
				panic(p)
			}
		}
		x.asked = true
		return replay, finish, true
	}
	a.mu.Unlock()
	discard()
	select {
	case <-e.done:
	case <-r.Context().Done():
		return w, func() {}, false
	case <-a.ctx.Done():
		return w, func() {}, false
	}
	a.mu.Lock()
	replay := e.replay
	if replay == nil {
		a.mu.Unlock()
		closeHTTPUpload(w, r)
		http.Error(w, "approved retry response is not replayable; no duplicate upstream request was sent", http.StatusServiceUnavailable)
		return w, func() {}, false
	}
	header, status, body, release, valid := replay.acquire()
	a.mu.Unlock()
	if !valid {
		closeHTTPUpload(w, r)
		http.Error(w, "approved retry response is not replayable; no duplicate upstream request was sent", http.StatusServiceUnavailable)
		return w, func() {}, false
	}
	defer release()
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(l.opts.WriteStallTimeout))
	defer controller.SetWriteDeadline(time.Time{}) //nolint:errcheck // fake writers need not implement deadlines
	copyHeader(w.Header(), header)
	w.WriteHeader(status)
	_, _ = w.Write(body)
	return w, func() {}, false
}

type askReplay struct {
	mu          sync.Mutex
	writer      http.ResponseWriter
	body        *held
	header      http.Header
	status      int
	valid       bool
	readers     int
	dropPending bool
}

func (w *askReplay) Header() http.Header         { return w.writer.Header() }
func (w *askReplay) Unwrap() http.ResponseWriter { return w.writer }
func (w *askReplay) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.writer.WriteHeader(status)
		return
	}
	w.mu.Lock()
	if w.status == 0 {
		w.status = status
		size := 0
		for k, vs := range w.writer.Header() {
			size += len(k)
			for _, v := range vs {
				size += len(v)
			}
		}
		if size > 32<<10 || len(w.writer.Header()) > 128 {
			w.valid = false
		} else {
			w.header = w.writer.Header().Clone()
		}
	}
	w.mu.Unlock()
	w.writer.WriteHeader(status)
}
func (w *askReplay) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.writer.Write(data)
	w.mu.Lock()
	if !w.valid || w.body.write(data[:n]) != n || err != nil {
		w.valid = false
	}
	w.mu.Unlock()
	return n, err
}
func (w *askReplay) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.writer).Flush()
}
func (w *askReplay) finish(ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.valid = w.valid && ok && w.status != 0 && len(w.header.Values("Trailer")) == 0
	if !w.valid {
		w.body.drop()
	}
}
func (w *askReplay) drop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.valid = false
	if w.readers == 0 {
		w.body.drop()
	} else {
		w.dropPending = true
	}
}

// Acquire pins the already bounded replay buffer while a retry writes it. It
// does not create another full-response allocation for each concurrent retry.
func (w *askReplay) acquire() (http.Header, int, []byte, func(), bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid {
		return nil, 0, nil, func() {}, false
	}
	w.readers++
	return w.header.Clone(), w.status, w.body.bytes(), func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.readers--
		if w.readers == 0 && w.dropPending {
			w.body.drop()
			w.dropPending = false
		}
	}, true
}
