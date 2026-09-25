// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// refSteps is Steps as it was before P8 (commit 2424655), kept verbatim but for its name: it copies every
// thread's state for every action and never forgets a thread; but for Exit, which ends the wait of the
// exiting process's threads, and R40/R42 (side traffic, tool windows and tids), which it reads off a full
// scan of every window and thread for every action, and R42's late actions, which it answers from a copy of
// the whole state after every transition (the changes made since). The differential tests hold the
// incremental Steps to its answers.
type refSteps struct {
	mu        sync.Mutex
	next      int
	states    map[string]*StepState
	pids      map[string]int // the process of each thread's last model request
	tids      map[string]bool
	hosts     map[string]bool
	pairs     map[uint64]bool
	pairOrder []uint64
	windows   []refWindow
	// unknown are the windows whose state is not known: an unread request may have reported them, or their decision was
	// folded out of its reply's order.
	unknown  []refWindow
	lost     bool
	reported map[string]bool // ids reported while no window of them was open
	// answered says a thread's latest line of HTTP traffic was a response, not a model request.
	answered map[string]bool
	// unread is the number of steps opened before the latest model request that was not read, whose replies' decisions
	// open their windows of unknown state.
	unread int
	// log is every transition folded, in order (R42: a model request, a model answer, a reply's window, an
	// exit), with the time it took effect at and the state after it; last is the latest transition's time.
	log  []refTransition
	last uint64
}

// refTransition is one transition: mono is when it took effect, from is its own time (below mono when it was
// folded after a later one; mono when it had none), and snap and states the whole state after it.
type refTransition struct {
	mono, from uint64
	snap       *refSteps
	states     map[string]StepState
}

// refWindow is one open tool window: the tool_use id, and the thread and step of the reply that asked for it.
type refWindow struct {
	id, thread string
	step       int
}

func newRefSteps(hosts ...string) *refSteps {
	s := &refSteps{states: make(map[string]*StepState), pids: make(map[string]int), tids: make(map[string]bool),
		reported: make(map[string]bool), answered: make(map[string]bool)}
	if len(hosts) > 0 {
		s.hosts = make(map[string]bool, len(hosts))
		for _, h := range hosts {
			if h = agent.CanonicalHost(h); h != "" {
				s.hosts[h] = true
			}
		}
	}
	return s
}

func (s *refSteps) Apply(ev *record.Event) {
	if ev == nil {
		return
	}
	switch {
	case ev.Kind == record.KindSSLRequest:
		if s.open(ev) {
			s.transition(ev.MonoNS)
		}
	case ev.Kind == record.KindSSLResponse:
		s.mu.Lock()
		if _, ok := s.states[Thread(ev)]; ok {
			s.answered[Thread(ev)] = true
		}
		s.mu.Unlock()
		if s.answersModel(ev) {
			s.closeStep(Thread(ev))
			s.transition(ev.MonoNS)
		}
	case ev.Kind == record.KindDecision:
		if s.stampDecision(ev) {
			s.transition(ev.MonoNS)
		}
	case ev.Kind.IsAction():
		s.attribute(ev)
	}
}

// transition logs a transition at mono with a copy of the state after it: one with no time of its own or
// older than the latest transition takes effect at the latest.
func (s *refSteps) transition(mono uint64) {
	s.mu.Lock()
	t := refTransition{mono: max(mono, s.last), from: mono}
	if mono == 0 {
		t.from = t.mono
	}
	s.last = t.mono
	if t.mono == 0 {
		s.mu.Unlock()
		return // no transition has a time yet: no action can be late
	}
	t.snap = &refSteps{tids: maps.Clone(s.tids), windows: slices.Clone(s.windows), unknown: slices.Clone(s.unknown), lost: s.lost}
	s.mu.Unlock()
	t.states = s.States()
	s.log = append(s.log, t)
}

// asOf answers an action at a time before the latest transition from the state after the last transition
// that took effect by then; unattributed before every transition with a time, and when a transition folded
// after a later one happened by then but took effect after it.
func (s *refSteps) asOf(ev *record.Event) record.Attribution {
	unattributed := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	k := -1
	for i, t := range s.log {
		if t.from <= ev.MonoNS && ev.MonoNS < t.mono {
			return unattributed
		}
		if t.mono <= ev.MonoNS {
			k = i
		}
	}
	if k < 0 {
		return unattributed
	}
	return s.log[k].snap.byContent(s.log[k].states, ev)
}

func (s *refSteps) States() map[string]StepState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]StepState, len(s.states))
	for thread, st := range s.states {
		out[thread] = *st
	}
	return out
}

func (s *refSteps) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// open folds a request and reports whether it was a model request.
func (s *refSteps) open(ev *record.Event) bool {
	var p record.SSLRequestPayload
	if err := ev.DecodePayload(&p); err != nil {
		return false
	}
	model := !p.Side && (s.hosts == nil || p.Host == "" || s.hosts[agent.CanonicalHost(p.Host)])
	s.rememberPair(ev.Pair, model)
	if !model {
		return false
	}
	thread := Thread(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ToolResults == nil {
		// It may have reported any window of the run, or none of them.
		s.windows, s.unknown, s.unread = nil, append(s.unknown, s.windows...), s.next
	} else if !s.lost {
		for _, id := range *p.ToolResults {
			byID := func(w refWindow) bool { return w.id == id }
			if i := slices.IndexFunc(s.windows, byID); i >= 0 {
				s.windows = slices.Delete(s.windows, i, i+1)
			} else if i := slices.IndexFunc(s.unknown, byID); i >= 0 {
				s.unknown = slices.Delete(s.unknown, i, i+1)
			} else {
				s.reported[id] = true
			}
		}
	}
	st, ok := s.states[thread]
	if !ok {
		st = &StepState{}
		s.states[thread] = st
	}
	s.answered[thread] = false
	s.pids[thread] = ev.PID
	s.tids[thread] = ev.Source == record.SourceSSL && ev.TID != 0
	if p.RetryOf != "" && st.Step > 0 {
		st.InFlight = true
		return true
	}
	if st.InFlight && !(ev.Source == record.SourceForwarder && ev.TID == 0) {
		return true
	}
	s.next++
	st.Step, st.OpenSince, st.InFlight = s.next, ev.TS, true
	return true
}

// Exit ends the wait of every thread whose last model request came from pid, at the latest transition.
func (s *refSteps) Exit(pid int) {
	s.mu.Lock()
	for thread, p := range s.pids {
		if p == pid {
			s.states[thread].InFlight = false
		}
	}
	s.mu.Unlock()
	s.transition(0)
}

func (s *refSteps) rememberPair(pair uint64, model bool) {
	if pair == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pairs == nil {
		s.pairs = map[uint64]bool{}
	}
	if _, ok := s.pairs[pair]; !ok {
		s.pairOrder = append(s.pairOrder, pair)
	}
	s.pairs[pair] = model
	for len(s.pairOrder) > maxPairs {
		delete(s.pairs, s.pairOrder[0])
		s.pairOrder = s.pairOrder[1:]
	}
}

func (s *refSteps) answersModel(ev *record.Event) bool {
	if ev.Pair == 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	model, ok := s.pairs[ev.Pair]
	if !ok {
		return true
	}
	delete(s.pairs, ev.Pair)
	return model
}

func (s *refSteps) closeStep(thread string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.states[thread]; ok {
		st.InFlight = false
	}
}

func (s *refSteps) attribute(ev *record.Event) {
	if (ev.Attr == nil || !richerThanTime(ev.Attr.Method)) && ev.MonoNS != 0 && ev.MonoNS < s.last {
		attr := s.asOf(ev)
		ev.Attr = &attr
		return
	}
	states := s.States()
	attr := s.byContent(states, ev)
	ev.Attr = &attr
}

// byContent is R42 over the full snapshot: the action's own uprobe-named thread first, then the one window of the
// run, then time.
func (s *refSteps) byContent(states map[string]StepState, ev *record.Event) record.Attribution {
	if ev.Attr != nil && richerThanTime(ev.Attr.Method) {
		return *ev.Attr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	thread := Thread(ev)
	if st, ok := states[thread]; ok && ev.TID != 0 && s.tids[thread] && st.Step > 0 {
		var mine []refWindow
		for _, w := range s.windows {
			if w.thread == thread {
				mine = append(mine, w)
			}
		}
		unknown := slices.ContainsFunc(s.unknown, func(w refWindow) bool { return w.thread == thread })
		if !s.lost && !st.InFlight && len(mine) == 1 && !unknown {
			return *record.AttributedByToolUse(thread, mine[0].step, mine[0].id)
		}
		return *record.AttributedByTID(thread, st.Step)
	}
	inflight := false
	for _, st := range states {
		inflight = inflight || (st.Step > 0 && st.InFlight)
	}
	if !s.lost && !inflight && len(s.windows) == 1 && len(s.unknown) == 0 {
		w := s.windows[0]
		return *record.AttributedByToolUse(w.thread, w.step, w.id)
	}
	return AttributeByTime(states, ev)
}

// stampDecision stamps a decision's step and reports whether it opened a tool window.
func (s *refSteps) stampDecision(ev *record.Event) bool {
	var p record.DecisionPayload
	if err := ev.DecodePayload(&p); err != nil {
		return false
	}
	step := p.Step
	s.mu.Lock()
	if st, ok := s.states[Thread(ev)]; ok && step == 0 {
		step = st.Step
	}
	s.mu.Unlock()
	if step == 0 {
		step = AttributeByTime(s.States(), ev).Step
	}
	window := p.ToolUseID != "" && !p.Unparsed && step != 0
	if window {
		s.mu.Lock()
		_, stated := s.states[Thread(ev)]
		inOrder := !stated || s.answered[Thread(ev)] // no model request of its thread since its response
		byID := func(w refWindow) bool { return w.id == p.ToolUseID }
		if s.reported[p.ToolUseID] {
			delete(s.reported, p.ToolUseID)
		} else if !s.lost {
			s.windows = slices.DeleteFunc(s.windows, byID)
			s.unknown = slices.DeleteFunc(s.unknown, byID)
			w := refWindow{id: p.ToolUseID, thread: Thread(ev), step: step}
			switch {
			case len(s.windows)+len(s.unknown) >= MaxToolWindows:
				s.lost, s.windows, s.unknown = true, nil, nil
			case !inOrder || step <= s.unread:
				s.unknown = append(s.unknown, w)
			default:
				s.windows = append(s.windows, w)
			}
		}
		s.mu.Unlock()
	}
	if step == 0 || p.Step != 0 {
		return window
	}
	p.Step = step
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(ev.Payload, &fields); err != nil {
		return window
	}
	encoded, err := json.Marshal(p.Step)
	if err != nil {
		return window
	}
	fields["step"] = encoded
	if raw, err := json.Marshal(fields); err == nil {
		ev.Payload = raw
	}
	return window
}

// streamGen makes a random event stream a run could produce: model and other requests, with and without
// pair tokens and retries, responses, decisions, actions with and without a richer attribution, and the
// exits of the processes the threads belong to. Threads are tid 1..threads, grouped three to a process;
// tid 0 events are keyed by their pid and one of three lanes, as Thread does.
type streamGen struct {
	r       *rand.Rand
	threads int
	// timed gives lines monotonic times, clock being the latest in order's.
	timed    bool
	clock    uint64
	nextPair uint64
	open     []uint64 // pair tokens of requests not yet answered
	exited   map[int]bool
	// reuse lets a tid speak again after its process exited, as a reused tid or a queued event does.
	reuse bool
}

// step is one element of a stream: an event, or the exit of a process (exit > 0).
type step struct {
	ev   *record.Event
	exit int
}

func pidOf(tid int) int { return 1000 + tid/3 }

func (g *streamGen) next() step {
	tid := 1 + g.r.IntN(g.threads)
	pid := pidOf(tid)
	if !g.reuse {
		for tries := 0; g.exited[pid] && tries < 100; tries++ {
			tid = 1 + g.r.IntN(g.threads)
			pid = pidOf(tid)
		}
		if g.exited[pid] {
			return step{ev: g.event(record.KindFS, 0, pid)} // every process is gone: an action from elsewhere
		}
	}
	if g.r.IntN(20) == 0 {
		tid = 0 // keyed by pid
	}
	switch k := g.r.IntN(100); {
	case k < 6:
		g.exited[pid] = true
		return step{exit: pid}
	case k < 30:
		return step{ev: g.request(tid, pid)}
	case k < 50:
		return step{ev: g.response(tid, pid)}
	case k < 60:
		return step{ev: g.decision(tid, pid)}
	default:
		return step{ev: g.action(tid, pid)}
	}
}

// event makes one line. Its monotonic time is the stream's clock, which moves on by 0, 5 or 10 a line so that
// lines share times; one line in twenty has none, and an action in three or another line in ten is late: up
// to 60 back, which is fewer transitions than Steps remembers, since a late transition takes effect at the
// latest one's time and those are at most 13 apart in 60.
func (g *streamGen) event(kind record.Kind, tid, pid int) *record.Event {
	e := &record.Event{V: record.Version, TS: time.Unix(1_800_000_000+int64(g.nextPair), 0).UTC(),
		PID: pid, TID: tid, Kind: kind, Source: record.SourceForwarder}
	if kind.IsAction() {
		e.Source = record.SourceKernel
	} else if tid == 0 {
		e.Lane = uint64(1 + g.r.IntN(3)) // a forwarder line names its process's lane (Thread)
	}
	if !g.timed {
		return e
	}
	g.clock += 5 * uint64(g.r.IntN(3))
	switch e.MonoNS = g.clock; {
	case g.r.IntN(20) == 0:
		e.MonoNS = 0
	case kind.IsAction() && g.r.IntN(3) == 0, g.r.IntN(10) == 0:
		if back := uint64(1 + g.r.IntN(60)); back < g.clock {
			e.MonoNS = g.clock - back
		}
	}
	return e
}

func (g *streamGen) request(tid, pid int) *record.Event {
	e := g.event(record.KindSSLRequest, tid, pid)
	host := "api.anthropic.com"
	switch g.r.IntN(6) {
	case 0:
		host = "github.com"
	case 1:
		host = "API.anthropic.com:443"
	case 2:
		host = ""
	}
	p := record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages", Host: host}
	if g.r.IntN(5) == 0 {
		p.RetryOf = "req-1"
	}
	if g.r.IntN(10) == 0 {
		p.Side = true
	}
	switch g.r.IntN(3) {
	case 1:
		p.ToolResults = &[]string{}
	case 2:
		ids := []string{}
		for i := range 4 {
			if g.r.IntN(2) == 0 {
				ids = append(ids, "toolu_"+strconv.Itoa(i))
			}
		}
		p.ToolResults = &ids
	}
	if tid != 0 && g.r.IntN(2) == 0 {
		e.Source = record.SourceSSL
	}
	if g.r.IntN(2) == 0 {
		g.nextPair++
		e.Pair = g.nextPair
		g.open = append(g.open, e.Pair)
	}
	mustPayload(e, p)
	return e
}

func (g *streamGen) response(tid, pid int) *record.Event {
	e := g.event(record.KindSSLResponse, tid, pid)
	if len(g.open) > 0 && g.r.IntN(3) != 0 {
		i := g.r.IntN(len(g.open))
		e.Pair = g.open[i]
		g.open = append(g.open[:i], g.open[i+1:]...)
	} else if g.r.IntN(4) == 0 {
		e.Pair = 1 << 40 // a token no request carried
	}
	mustPayload(e, record.SSLResponsePayload{Status: 200, ParserVersion: "x"})
	return e
}

func (g *streamGen) decision(tid, pid int) *record.Event {
	e := g.event(record.KindDecision, tid, pid)
	p := record.DecisionPayload{ToolUseID: "toolu_" + strconv.Itoa(g.r.IntN(4)), Tool: "bash", InputHash: "x"}
	if g.r.IntN(4) == 0 {
		p.Step = 7 // the parser's own number, which is never replaced
	}
	switch g.r.IntN(10) {
	case 0:
		p.ToolUseID = "" // a text reply's marker, or a parser that names no id
	case 1:
		p = record.DecisionPayload{Unparsed: true, Why: "schema"}
	}
	if tid != 0 && g.r.IntN(2) == 0 {
		e.Source = record.SourceSSL
	}
	mustPayload(e, p)
	return e
}

func (g *streamGen) action(tid, pid int) *record.Event {
	e := g.event(record.KindFS, tid, pid)
	switch g.r.IntN(5) {
	case 0:
		e.Attr = &record.Attribution{Thread: "tool-1", Step: 42, Confidence: record.ConfidenceExact, Method: record.MethodToolID}
	case 1:
		e.Attr = &record.Attribution{Thread: "t9", Step: 3, Confidence: record.ConfidenceLikely, Method: record.MethodTID}
	case 2:
		e.Attr = nil
	default:
		e.Attr = record.Unattributed()
	}
	mustPayload(e, record.FSPayload{Op: record.FSOpen, Path: "/work/a"})
	return e
}

func mustPayload(e *record.Event, p any) {
	if err := e.SetPayload(p); err != nil {
		panic(err)
	}
}

// clone copies what Apply may change: the attribution it replaces and the payload it rewrites.
func clone(e *record.Event) *record.Event {
	c := *e
	if e.Attr != nil {
		a := *e.Attr
		c.Attr = &a
	}
	c.Payload = bytes.Clone(e.Payload)
	return &c
}

// runDifferential feeds one random stream to Steps and to refSteps, the exits to Steps alone, and fails at
// the first event the two fold differently.
func runDifferential(t *testing.T, seed uint64, events, threads int, reuse bool, hosts ...string) map[string]int {
	t.Helper()
	derived := map[string]int{} // the methods the stage itself chose
	g := &streamGen{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), threads: threads,
		exited: map[int]bool{}, reuse: reuse, timed: true}
	got, want := NewSteps(hosts...), newRefSteps(hosts...)
	for i := range events {
		st := g.next()
		if st.exit != 0 {
			got.Exit(st.exit)
			want.Exit(st.exit)
			continue
		}
		a, b := st.ev, clone(st.ev)
		preset := a.Attr != nil && richerThanTime(a.Attr.Method)
		late := a.MonoNS != 0 && a.MonoNS < got.lastMono
		got.Apply(a)
		if a.Kind.IsAction() && !preset {
			derived[a.Attr.Method]++
			if late {
				derived["late "+a.Attr.Method+" "+a.Attr.Confidence]++
			}
		}
		want.Apply(b)
		if (a.Attr == nil) != (b.Attr == nil) || (a.Attr != nil && *a.Attr != *b.Attr) {
			t.Fatalf("seed %d event %d (%s, tid %d, pid %d): attribution %+v, the reference gives %+v",
				seed, i, a.Kind, a.TID, a.PID, a.Attr, b.Attr)
		}
		if !bytes.Equal(a.Payload, b.Payload) {
			t.Fatalf("seed %d event %d (%s, tid %d, pid %d): payload %s, the reference gives %s",
				seed, i, a.Kind, a.TID, a.PID, a.Payload, b.Payload)
		}
		if got.Count() != want.Count() {
			t.Fatalf("seed %d event %d: %d steps, the reference counts %d", seed, i, got.Count(), want.Count())
		}
	}
	// Every thread Steps still holds is in the state the reference holds it in.
	ref := want.States()
	for thread, st := range got.States() {
		if ref[thread] != st {
			t.Fatalf("seed %d: thread %s is %+v, the reference has %+v", seed, thread, st, ref[thread])
		}
	}
	return derived
}

// TestStepsMatchesTheReference holds the incremental attribution to the one it replaced over random
// streams, exits included: Steps must attribute every action, stamp every decision and count every step
// exactly as refSteps does, with or without declared hosts, and whether or not a tid speaks again after
// its process has exited. The lines carry monotonic times, some none and some late, so an action that
// arrives after a later transition is held to the state after the last transition before it (R42).
func TestStepsMatchesTheReference(t *testing.T) {
	derived := map[string]int{}
	for seed := range uint64(200) {
		for _, reuse := range []bool{false, true} {
			threads := 2 + int(seed%13)
			for _, hosts := range [][]string{{"api.anthropic.com"}, nil} {
				for m, n := range runDifferential(t, seed, 400, threads, reuse, hosts...) {
					derived[m] += n
				}
			}
		}
	}
	// The streams reach every rule R42 and R34 have, or the comparison proves nothing about one of them.
	for _, m := range []string{record.MethodToolID, record.MethodTID, record.MethodTime,
		"late tool_id likely", "late tid likely", "late time likely", "late time unattributed"} {
		if derived[m] == 0 {
			t.Errorf("no action of the random streams was attributed by %s: %v", m, derived)
		}
	}
}

// TestStepsRetiresExitedThreads is P8's other half: a thread whose process has exited leaves the live set,
// so a run that has seen more threads than maxRetired holds only its live ones and a bounded memory, while
// every attribution stays the reference's. Each process makes one model turn from one thread and exits;
// one in seven exits before its response arrives, which comes a few turns later.
func TestStepsRetiresExitedThreads(t *testing.T) {
	const n = maxRetired + 1500
	s, ref := NewSteps("api.anthropic.com"), newRefSteps("api.anthropic.com")
	g := &streamGen{r: rand.New(rand.NewPCG(1, 2)), exited: map[int]bool{}}
	both := func(e *record.Event) (*record.Event, *record.Event) {
		c := clone(e)
		s.Apply(e)
		ref.Apply(c)
		return e, c
	}
	var late []int // tids whose process exited with the response outstanding
	for tid := 1; tid <= n; tid++ {
		pid := 100000 + tid
		req := g.event(record.KindSSLRequest, tid, pid)
		mustPayload(req, record.SSLRequestPayload{Host: "api.anthropic.com"})
		both(req)
		if tid%7 == 0 {
			s.Exit(pid)
			ref.Exit(pid)
			late = append(late, tid)
			continue
		}
		if tid%5 == 0 || len(late) > 0 && tid%3 == 0 {
			a, b := both(g.action(0, 1))
			if *a.Attr != *b.Attr {
				t.Fatalf("thread %d: attribution %+v, the reference gives %+v", tid, a.Attr, b.Attr)
			}
		}
		if len(late) > 2 {
			both(g.event(record.KindSSLResponse, late[0], 100000+late[0]))
			late = late[1:]
		}
		both(g.event(record.KindSSLResponse, tid, pid))
		dec := g.event(record.KindDecision, tid, pid)
		mustPayload(dec, record.DecisionPayload{ToolUseID: "toolu_1", Tool: "bash", InputHash: "x"})
		if a, b := both(dec); !bytes.Equal(a.Payload, b.Payload) {
			t.Fatalf("thread %d: decision %s, the reference gives %s", tid, a.Payload, b.Payload)
		}
		s.Exit(pid)
		ref.Exit(pid)
	}
	if s.Count() != ref.Count() {
		t.Fatalf("%d steps, the reference counts %d", s.Count(), ref.Count())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.retired) > maxRetired || len(s.retiredOrder) > maxRetired {
		t.Errorf("%d retired threads remembered (%d in order), the bound is %d", len(s.retired), len(s.retiredOrder), maxRetired)
	}
	// Live: nothing, an exit ends the wait of a thread whose response is outstanding.
	if len(s.states) != 0 || len(s.inflight) != 0 {
		t.Errorf("%d threads live and %d in flight after %d turns, want none",
			len(s.states), len(s.inflight), n)
	}
	if len(s.byPID) != 0 {
		t.Errorf("%d processes still named after every one exited", len(s.byPID))
	}
}

// TestStepsExitEndsWait: an exit while the thread's response is outstanding ends the wait, so a dead
// process's unanswered request neither holds an action's attribution nor counts as a second in-flight
// thread; its decisions still take its own step, and a late response is a no-op.
func TestStepsExitEndsWait(t *testing.T) {
	s := NewSteps("api.anthropic.com")
	req := func(tid, pid int) *record.Event {
		e := &record.Event{Kind: record.KindSSLRequest, TID: tid, PID: pid}
		mustPayload(e, record.SSLRequestPayload{Host: "api.anthropic.com"})
		return e
	}
	s.Apply(req(1, 10)) // step 1, never answered
	s.Exit(10)
	s.Apply(req(2, 20)) // step 2
	s.Apply(&record.Event{Kind: record.KindSSLResponse, TID: 2, PID: 20})
	act := &record.Event{Kind: record.KindFS, TID: 2, PID: 20}
	s.Apply(act)
	if act.Attr.Confidence != record.ConfidenceUnattributed {
		t.Fatalf("no step is open, yet an action was attributed: %+v", act.Attr)
	}
	s.Apply(req(3, 30)) // step 3
	act = &record.Event{Kind: record.KindFS, TID: 4, PID: 40}
	s.Apply(act)
	if act.Attr.Step != 3 || act.Attr.Thread != "t3" || act.Attr.Confidence != record.ConfidenceLikely {
		t.Fatalf("with one live thread in flight the action went to %+v, want t3's step 3", act.Attr)
	}
	s.Apply(&record.Event{Kind: record.KindSSLResponse, TID: 1, PID: 10}) // late
	dec := &record.Event{Kind: record.KindDecision, TID: 1, PID: 10}
	mustPayload(dec, record.DecisionPayload{ToolUseID: "toolu_1", Tool: "bash", InputHash: "x"})
	s.Apply(dec)
	var p record.DecisionPayload
	if err := dec.DecodePayload(&p); err != nil || p.Step != 1 {
		t.Fatalf("the retired thread's decision took step %d (%v), want its own step 1", p.Step, err)
	}
	if len(s.inflight) != 1 {
		t.Fatalf("%d threads in flight, want only t3", len(s.inflight))
	}
}

// BenchmarkStepsExit measures a retirement: one thread's turn and its process's exit per operation, in a
// run that has already retired far more threads than it remembers.
func BenchmarkStepsExit(b *testing.B) {
	s := NewSteps()
	ev := func(kind record.Kind, tid int) *record.Event {
		e := &record.Event{Kind: kind, TID: tid, PID: tid}
		if kind == record.KindSSLRequest {
			mustPayload(e, record.SSLRequestPayload{Host: "api.anthropic.com"})
		}
		return e
	}
	tid := 0
	b.ReportAllocs()
	for b.Loop() {
		tid++
		s.Apply(ev(record.KindSSLRequest, tid))
		s.Apply(ev(record.KindSSLResponse, tid))
		s.Exit(tid)
	}
	if len(s.retired) > maxRetired {
		b.Fatal(fmt.Sprint(len(s.retired), " retired threads remembered"))
	}
}
