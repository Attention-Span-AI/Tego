// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"encoding/json"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// StepState is one thread's place in the run's model turns: the step its last request opened, when it
// opened, and whether the response is still outstanding.
type StepState struct {
	Step      int
	OpenSince time.Time
	InFlight  bool
}

// Steps numbers a run's model turns and attributes its action events to them — E28a, "steps by time".
//
// It derives everything from the event stream itself, in order, so it works identically behind the
// forwarder, behind the uprobes and over a ledger a view replays: an ssl_request to a declared models[]
// host opens the next step for the thread that made it (a retry extends the original instead, R23/R33),
// the matching ssl_response ends the wait, and an action event in between is attributed to the one open
// step (R34). Step numbers come from one counter shared by every thread, so comparing steps across
// threads means something (R36).
//
// A step stays the thread's current step after its response arrives, until that thread's next request
// opens the next one. R33 describes the window as ending at the response; taken literally, nothing
// would ever be attributed, because an agent runs its tools after the model answers — every exec, open
// and connect of a turn happens in exactly that interval. The acceptance line ("a 20-step run
// attributes every action to a step") only holds under the reading implemented here, so the window is
// extended past the response and the divergence is stated rather than hidden. The counting rules of R34
// are unchanged: one candidate is likely, zero or several are unattributed, and nothing is ever guessed.
//
// The attribute stage runs on the pipeline's one goroutine for every event of the run, so what it costs
// per event must not grow with the threads the run has seen: it keeps the in-flight threads apart and
// counts the threads with a step, which is all R34's rule reads (byTime). It used to copy and scan every thread's state for every action, 0.2 ms an event at a
// thousand threads and 3 ms at ten thousand, which is where a queue starts dropping events. A thread
// whose process has exited is retired (Exit), so the state a run holds is its live threads and a bounded
// memory of retired ones; retiring changes no attribution (see Exit).
type Steps struct {
	mu   sync.Mutex
	next int
	// states is every thread that has opened a step and is not retired.
	states map[string]*threadState
	// inflight is the threads of states whose response is still outstanding.
	inflight map[string]*threadState
	// stepped counts every thread that has ever opened a step, retired ones included, and solo names
	// that thread while there is exactly one: R34's "the one thread that has a step".
	stepped int
	solo    string
	// retired keeps the state of a thread retired by Exit, so an event of it still queued behind the exit
	// is folded as if the thread had never been retired; bounded by maxRetired, oldest first.
	retired      map[string]retiredState
	retiredOrder []retiredRef
	retiredSeq   uint64
	// byPID names the threads of each process that opened a step, which is what an exit is reported by.
	byPID map[int][]string
	hosts map[string]bool
	// pairs remembers, by the in-process pair token (record.Event.Pair), whether an ssl_request was a
	// model request, so its response closes the thread's model step only when it answers one. On one
	// thread (an event loop) the answer to a non-model request closed the model step still in flight.
	pairs     map[uint64]bool
	pairOrder []uint64
	// pairThread names the thread a remembered pair's request came from, which is how Abandon finds it.
	pairThread map[uint64]string
	// abandoned holds pairs Abandon was told of before their ssl_request reached the stage; bounded by maxPairs.
	abandoned      map[uint64]bool
	abandonedOrder []uint64 // insertion order of abandoned, oldest first; a pair open() took stays until evicted
	// windows are the tool windows open in the run, by tool_use id (E29, R42): a reply asked for the tool and no
	// model request has reported its result yet. threadWindows lists them by the thread whose reply opened them.
	windows       map[string]toolWindow
	threadWindows map[string][]string
	// unknown are the windows whose state is not known, by tool_use id, each with the thread whose reply asked for it: a
	// request may have reported its result, or its tool may still run (an unread request, a decision folded out of order).
	// threadUnknown counts them by that thread. While any is, no window is the run's only one, nor its thread's.
	unknown       map[string]string
	threadUnknown map[string]int
	// windowsLost is set once more than MaxToolWindows were open or of unknown state at once: the stage stops reading
	// windows for the run, since one it did not keep could make another look like the only one.
	windowsLost bool
	// reported holds the tool_use ids a model request reported a result for while no window of them was open, so a
	// reply's decision folded after that request opens none (openWindow); bounded by MaxUnopenedResults, oldest first.
	reported      map[string]uint64
	reportedOrder []reportRef
	reportedSeq   uint64
	// unreadBelow is one past the steps opened before the latest model request derive did not read: that request may
	// have reported any of their replies' tools, so a decision numbered into one of them opens its window as one of
	// unknown state (openWindow).
	unreadBelow int
	// tidNamed says a model request of the run has named its thread by its tid, so rule (1) may apply to its actions.
	tidNamed bool
	// lastMono is the monotonic time of the latest transition, and epochs (a ring of nEpochs from headEpoch) what
	// each recent one changed, for an action that arrives after a later transition (asOf). touched collects, while a
	// transition is folded, rule (1)'s answer for each thread it changes from before the change; touchedAll says it
	// changed more than maxTouched threads'.
	lastMono           uint64
	epochs             *[maxEpochs]epoch
	headEpoch, nEpochs int
	touched            []ownAnswer
	touchedAll         bool
}

// toolWindow is one reply's tool_use whose result no request has reported: the thread the reply came on and its step.
type toolWindow struct {
	thread string
	step   int
}

// MaxToolWindows bounds the tool windows open or of unknown state at once in a run; past it the stage attributes by tid
// and time alone.
const MaxToolWindows = 4096

// threadState is one live thread: its step, the process it last made a model request from (listed says
// byPID names it there).
type threadState struct {
	StepState
	pid    int
	listed bool
	// pair is the pair token of the thread's latest model request, which Abandon matches.
	pair uint64
	// tid says the thread's latest model request came from a source that names the writing thread by its tid (the
	// uprobe source), so an action carrying that tid is the thread's own (R42). A forwarder thread is named after
	// its process and a lane, and no action's tid says anything about it.
	tid bool
	// answered says a response of the thread was folded after its latest model request, so a decision of the thread
	// folded now is that response's, in the order a source writes a reply's lines (stampDecision).
	answered bool
}

// retiredState is a retired thread's last state, and which retirement put it there.
type retiredState struct {
	StepState
	tid, answered bool
	seq           uint64
}

// retiredRef is one retirement, in the order retirements happened.
type retiredRef struct {
	thread string
	seq    uint64
}

// maxPairs bounds the pairs remembered; a request whose response never comes is forgotten oldest first.
const maxPairs = 4096

// maxRetired bounds the retired threads remembered. An event of a retired thread is only ever one the
// pipeline had queued when the thread's process exited, so the memory needs to outlast a queue's worth of
// exits, not the run.
const maxRetired = 4096

// NewSteps tracks the declared models[] hosts. With none, every ssl_request opens a step — which is
// what the forwarder produces, since a listener only ever serves a declared entry.
func NewSteps(hosts ...string) *Steps {
	s := &Steps{
		states:   make(map[string]*threadState),
		inflight: make(map[string]*threadState),
		retired:  make(map[string]retiredState),
		byPID:    make(map[int][]string),
	}
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

// Thread names the thread an event came from, the key a step is opened for. A line whose source knows its
// process and not its thread (the forwarder) carries a lane instead of a tid: its turns in flight at once are
// apart, lane 1 keeps the process's own name, and a later lane is named after it (R34).
func Thread(ev *record.Event) string {
	tid := ev.TID
	if tid == 0 {
		tid = ev.PID
	}
	if ev.TID == 0 && ev.Lane > 1 {
		return "t" + strconv.Itoa(tid) + "." + strconv.FormatUint(ev.Lane, 10)
	}
	return "t" + strconv.Itoa(tid)
}

// Apply folds one event into the state and attributes it. Events must arrive in stream order, which is
// the order the pipeline hands them over and the order a ledger stores them.
func (s *Steps) Apply(ev *record.Event) {
	if ev == nil {
		return
	}
	switch {
	case ev.Kind == record.KindSSLRequest:
		s.open(ev)
	case ev.Kind == record.KindSSLResponse:
		s.answer(ev)
	case ev.Kind == record.KindDecision:
		s.stampDecision(ev)
	case ev.Kind.IsAction():
		s.attribute(ev)
	}
}

// Stage is the pipeline's attribute stage (P0-DESIGN §4.1 step 4) in the shape runtime.Compose takes.
func (s *Steps) Stage(next func(*record.Event)) func(*record.Event) {
	return func(ev *record.Event) {
		s.Apply(ev)
		next(ev)
	}
}

// States is a copy of what each live thread is doing, for a view or a test; a retired thread is not in it.
func (s *Steps) States() map[string]StepState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]StepState, len(s.states))
	for thread, st := range s.states {
		out[thread] = st.StepState
	}
	return out
}

// Count is how many steps the run has opened so far (R36).
func (s *Steps) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// Exit retires the threads of process pid: the run's kernel record reports the exit of a process's
// thread group, its last thread's, the moment none of its threads can make another request
// (source.ProcessHook). It reported the leader's, after which the other threads could go on.
// A retired thread's state leaves the live set, and its step is remembered (maxRetired) together with
// the counts R34 reads, so retiring changes no attribution: it still counts as a thread with a step,
// and an event of it that the pipeline had queued before the exit reached this method — the exit comes
// from the recorder's own goroutine, not through the queue — brings it back exactly as it was. A thread
// whose response is still outstanding stops being in flight: its process is gone, so the response is never
// read by it (the uprobe path reports a request whose connection died as unmetered and emits no
// response), and leaving it in flight would misattribute or unattribute every later action.
//
// Only a thread that comes back after maxRetired later retirements is folded as new, and even then no
// action changes its attribution: that many retirements mean more than one thread has had a step, so
// R34 decides by the in-flight threads alone. What can differ is that thread's own decision lines, and a
// retry as its first request, which opens a step where the thread's old state would have continued one; a
// process that reused the tid makes neither before a request of its own.
func (s *Steps) Exit(pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, thread := range s.byPID[pid] {
		st, ok := s.states[thread]
		if !ok || st.pid != pid {
			continue // retired already, or the tid is now another process's
		}
		s.touch(thread)
		s.setInFlight(thread, st, false) // an exit ends the wait: a dead process's response never comes
		s.retire(thread, st)
	}
	delete(s.byPID, pid)
	s.transition(0) // the exit's own time is not known here: it takes effect at the latest transition
}

// retire moves a live thread that is not in flight to the retired memory; s.mu must be held.
func (s *Steps) retire(thread string, st *threadState) {
	delete(s.states, thread)
	s.retiredSeq++
	s.retired[thread] = retiredState{StepState: st.StepState, tid: st.tid, answered: st.answered, seq: s.retiredSeq}
	s.retiredOrder = append(s.retiredOrder, retiredRef{thread: thread, seq: s.retiredSeq})
	for len(s.retiredOrder) > maxRetired {
		old := s.retiredOrder[0]
		s.retiredOrder = s.retiredOrder[1:]
		if r, ok := s.retired[old.thread]; ok && r.seq == old.seq {
			s.touch(old.thread) // forgotten, its actions are no longer its own (rule (1))
			delete(s.retired, old.thread)
		}
	}
}

// live returns the thread's state, bringing a retired thread back as it was but for answered, which the model
// request it is called for clears; nil when the thread has never opened a step, or was forgotten. s.mu must be held.
func (s *Steps) live(thread string) *threadState {
	if st, ok := s.states[thread]; ok {
		return st
	}
	r, ok := s.retired[thread]
	if !ok {
		return nil
	}
	delete(s.retired, thread)
	st := &threadState{StepState: r.StepState, tid: r.tid}
	s.states[thread] = st
	return st
}

// track records that thread's last model request came from process pid, listing it under pid once; a
// tid another process now uses is listed under both, and the first one's exit passes it over (Exit).
// s.mu must be held.
func (s *Steps) track(thread string, st *threadState, pid int) {
	if st.listed && st.pid == pid {
		return
	}
	st.pid, st.listed = pid, true
	s.byPID[pid] = append(s.byPID[pid], thread)
}

// setInFlight keeps inflight equal to the live threads whose response is outstanding; s.mu must be held.
func (s *Steps) setInFlight(thread string, st *threadState, on bool) {
	st.InFlight = on
	if on {
		s.inflight[thread] = st
		return
	}
	delete(s.inflight, thread)
}

// open starts the next step for the requesting thread, or extends the one already in flight. A retry
// never opens a step: it repeats a request whose step is already open or just closed (R23, R33). A model host's
// side traffic is no model request (R40). Every model request closes the tool windows whose results it reports,
// and leaves every window of the run of unknown state when it was not read (R42).
func (s *Steps) open(ev *record.Event) {
	var p record.SSLRequestPayload
	if err := ev.DecodePayload(&p); err != nil {
		return
	}
	model := !p.Side && (s.hosts == nil || p.Host == "" || s.hosts[agent.CanonicalHost(p.Host)])
	thread := Thread(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rememberPair(ev.Pair, model, thread)
	if !model {
		return
	}
	s.touch(thread)
	s.closeWindows(p.ToolResults)
	defer s.transition(ev.MonoNS) // runs before the unlock, after every change below
	st := s.live(thread)
	if st == nil {
		// A thread's first model request always opens a step, and only then does it count.
		st = &threadState{}
		s.states[thread] = st
		s.stepped++
		if s.stepped == 1 {
			s.solo = thread
		}
	}
	s.track(thread, st, ev.PID)
	st.pair, st.answered = ev.Pair, false
	st.tid = ev.Source == record.SourceSSL && ev.TID != 0
	s.tidNamed = s.tidNamed || st.tid
	if s.abandoned[ev.Pair] {
		// Its source gave up on the request before this line reached the stage: it opens a step (or joins
		// the open one) and is not left in flight.
		delete(s.abandoned, ev.Pair)
		defer func() {
			if st.pair == ev.Pair {
				s.setInFlight(thread, st, false)
			}
		}()
	}
	if p.RetryOf != "" && st.Step > 0 {
		s.setInFlight(thread, st, true) // the original's step continues
		return
	}
	if st.InFlight && !(ev.Source == record.SourceForwarder && ev.TID == 0) {
		return // a second request while one is outstanding stays inside the open step (R33)
	}
	// The forwarder frees a lane only after its exchange is recorded, so a second non-retry request on a
	// thread still in flight follows a turn that never got an ssl_response (an upstream leg that failed
	// before headers, a client that left): it is a new turn, and the abandoned step is left behind.
	s.next++
	st.Step, st.OpenSince = s.next, ev.TS
	s.setInFlight(thread, st, true)
}

// rememberPair records whether the request carrying pair was a model request; s.mu must be held.
func (s *Steps) rememberPair(pair uint64, model bool, thread string) {
	if pair == 0 {
		return
	}
	if s.pairs == nil {
		s.pairs = map[uint64]bool{}
	}
	if s.pairThread == nil {
		s.pairThread = map[uint64]string{}
	}
	if _, ok := s.pairs[pair]; !ok {
		s.pairOrder = append(s.pairOrder, pair)
	}
	s.pairs[pair] = model
	s.pairThread[pair] = thread
	for len(s.pairOrder) > maxPairs {
		delete(s.pairs, s.pairOrder[0])
		delete(s.pairThread, s.pairOrder[0])
		s.pairOrder = s.pairOrder[1:]
	}
}

// Abandon tells the stage that the source gave up on the request carrying pair: its connection was lost or
// closed, or its response was given up waiting for, so no ssl_response will end its wait. The thread's step
// stays its current one but is no longer in flight, so the thread's next turn opens a new step instead of
// joining this one and no stale in-flight entry unattributes other threads' actions (R33). A request that
// is not the thread's latest is left alone: a later request is still outstanding. A pair whose
// ssl_request has not reached the stage yet is remembered and closed when it does.
func (s *Steps) Abandon(pair uint64) {
	if pair == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	thread, ok := s.pairThread[pair]
	if !ok {
		if s.abandoned == nil {
			s.abandoned = map[uint64]bool{}
		}
		if s.abandoned[pair] {
			return
		}
		// Past the bound the oldest entry goes, one at a time: emptying the map dropped every earlier pair
		// whose request was still on its way, and each was left in flight for good.
		for len(s.abandonedOrder) >= maxPairs {
			delete(s.abandoned, s.abandonedOrder[0])
			s.abandonedOrder = s.abandonedOrder[1:]
		}
		s.abandoned[pair] = true
		s.abandonedOrder = append(s.abandonedOrder, pair)
		return
	}
	delete(s.pairs, pair)
	delete(s.pairThread, pair)
	if st, ok := s.states[thread]; ok && st.pair == pair && st.InFlight {
		s.touch(thread)
		s.setInFlight(thread, st, false)
		s.transition(0) // given up on now: it takes effect at the latest transition
	}
}

// answer folds a response: it ends the wait of the thread's model step when it answers a model request, and the
// decisions its source writes after it are its own (answered).
func (s *Steps) answer(ev *record.Event) {
	thread := Thread(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.states[thread]; ok {
		st.answered = true
	} else if r, ok := s.retired[thread]; ok {
		r.answered = true
		s.retired[thread] = r
	}
	if s.answersModel(ev) {
		s.touch(thread)
		s.closeStep(thread)
		s.transition(ev.MonoNS)
	}
}

// answersModel reports whether a response answers a model request: by its pair token when the request was
// seen with one, and otherwise as before, since a response with no known request can only be assumed to
// close the thread's step. s.mu must be held.
func (s *Steps) answersModel(ev *record.Event) bool {
	if ev.Pair == 0 {
		return true
	}
	model, ok := s.pairs[ev.Pair]
	if !ok {
		return true
	}
	delete(s.pairs, ev.Pair)
	delete(s.pairThread, ev.Pair)
	return model
}

// closeStep ends the wait for a thread's response. The step stays the thread's current one until its
// next request opens another. A retired thread is not in flight, so there is nothing to end (a response
// that arrives after its process's exit lands here). s.mu must be held.
func (s *Steps) closeStep(thread string) {
	st, ok := s.states[thread]
	if !ok {
		return
	}
	s.setInFlight(thread, st, false)
}

// attribute stamps one action event.
func (s *Steps) attribute(ev *record.Event) {
	s.mu.Lock()
	attr := s.byContent(ev)
	s.mu.Unlock()
	ev.Attr = &attr
}

// byContent is R42's rule, ahead of time's (R35); s.mu must be held. Every answer is likely: each reads what was
// on the wire and in the kernel record, and none of them can see what caused an action, so none is exact.
//
// An action carrying the tid of a thread the uprobe source named, while that thread has a step, is that thread's
// own (method tid): with exactly one of its replies' tool windows open, none of unknown state and no model request of
// its own in flight, it is that reply's (method tool_id), and otherwise its current step's. An action of any other
// thread falls in the one window open in the whole run, when exactly one is, none is of unknown state and no model
// request is in flight anywhere (method tool_id): the one tool the model asked for and has not been told the result
// of. Everything else is time's.
func (s *Steps) byContent(ev *record.Event) record.Attribution {
	if ev.Attr != nil && richerThanTime(ev.Attr.Method) {
		return *ev.Attr
	}
	// The thread an action names is "t<tid>" (Thread); it is built in a stack buffer, since naming it costs an
	// allocation on every action of every run and only rule (1)'s answer needs the name.
	var buf [24]byte
	var key []byte
	if ev.TID != 0 {
		key = strconv.AppendInt(append(buf[:0], 't'), int64(ev.TID), 10)
	}
	if ev.MonoNS != 0 && ev.MonoNS < s.lastMono {
		// It happened before a turn's transition the stage has already folded (the kernel's recorder can deliver an
		// action after the model traffic of a later turn): the state now says nothing about it, the state then does.
		return s.asOf(ev.MonoNS, key)
	}
	if key != nil {
		if st, ok := s.ownState(string(key)); ok {
			return s.ownAttribution(string(key), st)
		}
	}
	return s.byRun()
}

// byRun is rules (2) and (3), which read the run's state alone and so give every action outside rule (1) the same
// answer between two transitions; s.mu must be held.
func (s *Steps) byRun() record.Attribution {
	if !s.windowsLost && len(s.inflight) == 0 && len(s.windows) == 1 && len(s.unknown) == 0 {
		for id, w := range s.windows {
			return *record.AttributedByToolUse(w.thread, w.step, id)
		}
	}
	return s.byTime(nil)
}

// ownState is the state of the thread named thread (key, Thread's name for the tid an action carries), when that thread
// is one the uprobe source named and has a step: live or retired, so an action queued behind its process's exit reads
// as it would have before (R36). s.mu must be held.
func (s *Steps) ownState(thread string) (StepState, bool) {
	if st, ok := s.states[thread]; ok {
		return st.StepState, st.tid && st.Step > 0
	}
	r, ok := s.retired[thread]
	return r.StepState, ok && r.tid && r.Step > 0
}

// ownAttribution is rule (1)'s answer for an action of thread, whose state is st: with exactly one of its replies'
// tool windows open, none of unknown state and no model request of its own in flight, that reply's, and otherwise its
// current step's. A step stays the thread's until its next request (R33 as built), so an action the thread makes after
// its last reply is its last step's. s.mu must be held.
func (s *Steps) ownAttribution(thread string, st StepState) record.Attribution {
	if ids := s.threadWindows[thread]; !s.windowsLost && !st.InFlight && len(ids) == 1 && s.threadUnknown[thread] == 0 {
		return *record.AttributedByToolUse(thread, s.windows[ids[0]].step, ids[0])
	}
	return *record.AttributedByTID(thread, st.Step)
}

// ownAnswer is rule (1)'s answer for the actions of one thread at some time: ok is false when the rule did not apply to
// the thread then (it was no thread the uprobe source named, or had no step).
type ownAnswer struct {
	thread string
	attr   record.Attribution
	ok     bool
}

// maxTouched bounds the threads one epoch remembers rule (1)'s earlier answer for; a transition that changed more
// (an exit of a process with that many model threads, a request reporting or closing that many threads' windows, the
// windows lost while that many threads held one) keeps the first ones' and is taken as one that changed every other
// thread's. The first are in the order the transition changes them: an exit's threads, a request's results, the
// retirements as they happened, and the window holders by name (touchHolders).
const maxTouched = 64

// touch remembers rule (1)'s answer for thread's actions as it is before the transition being folded changes it; s.mu
// must be held, and every change a transition makes to a thread's step, flight, tid or windows comes after its touch.
func (s *Steps) touch(thread string) {
	if s.touchedAll || slices.ContainsFunc(s.touched, func(a ownAnswer) bool { return a.thread == thread }) {
		return
	}
	if len(s.touched) == maxTouched {
		s.touchedAll = true
		return
	}
	a := ownAnswer{thread: thread}
	if st, ok := s.ownState(thread); ok {
		a.attr, a.ok = s.ownAttribution(thread, st), true
	}
	s.touched = append(s.touched, a)
}

// epoch is one transition the stage folded (a model request, a model answer, a reply's tool window, a wait an exit or
// an abandoned request ended), with what it changed, so an action that happened before a later transition can be
// answered as the state was at its time (asOf).
type epoch struct {
	// mono is when the epoch answers from: the transition's monotonic time. from is the earliest time a transition
	// folded into it happened at; it is below mono when one was folded after a later one, and the state between the
	// two is not known.
	mono, from uint64
	// attr is what rules (2) and (3) answered from mono on.
	attr record.Attribution
	// before is rule (1)'s answer, just before the epoch, for each thread the epoch changed; all says it changed more
	// threads' answers than it keeps, and tids that rule (1) may have applied to the ones it did not keep (tidNamed).
	before    []ownAnswer
	all, tids bool
}

// maxEpochs bounds the transitions remembered for actions that arrive late; one older than all of them is
// unattributed, never placed by a state it did not happen in.
const maxEpochs = 64

// transition records the state after a model request, answer, tool window, exit or abandoned request changed it, with
// what the change touched; s.mu must be held. The epochs stay in time order: a change with no monotonic time of its
// own (an exit, an abandoned request, a line without mono_ns) and one older than the latest transition are taken as at
// the latest transition, the order the stage folds them in, and an older one marks the interval from its own time as
// one whose state is not known.
func (s *Steps) transition(mono uint64) {
	defer func() { s.touched, s.touchedAll = s.touched[:0], false }()
	if mono == 0 && len(s.touched) == 0 && !s.touchedAll {
		return // nothing changed
	}
	from := mono
	if mono < s.lastMono {
		mono = s.lastMono
	}
	if from == 0 {
		from = mono
	}
	if mono == 0 {
		return // no transition has a time yet: no action can be late
	}
	s.lastMono = mono
	if s.epochs == nil {
		s.epochs = new([maxEpochs]epoch)
	}
	if s.nEpochs > 0 {
		if last := &s.epochs[(s.headEpoch+s.nEpochs-1)%maxEpochs]; last.mono == mono {
			// Folded into the latest epoch: it answers with the state after both, and a thread both changed keeps the
			// answer from before the first, which is the one an earlier time reads. Once the epoch has dropped a thread's
			// answer, a later answer of a thread it does not keep may be one the first changed, so none is added.
			last.attr, last.from, last.tids = s.byRun(), min(last.from, from), s.tidNamed
			for _, a := range s.touched {
				if last.all || slices.ContainsFunc(last.before, func(b ownAnswer) bool { return b.thread == a.thread }) {
					continue
				}
				if len(last.before) == maxTouched {
					last.all = true
					continue
				}
				last.before = append(last.before, a)
			}
			last.all = last.all || s.touchedAll
			return
		}
	}
	if s.nEpochs == maxEpochs {
		s.headEpoch = (s.headEpoch + 1) % maxEpochs
		s.nEpochs--
	}
	e := &s.epochs[(s.headEpoch+s.nEpochs)%maxEpochs]
	e.mono, e.from, e.attr, e.all, e.tids = mono, from, s.byRun(), s.touchedAll, s.tidNamed
	e.before = append(e.before[:0], s.touched...) // the slot's array is reused, so a ring that has filled allocates nothing
	s.nEpochs++
}

// asOf is the answer for an action at mono, a time before the latest transition, of the thread key names (nil: a line
// with no tid): the state of the epoch it fell in, which is rule (1)'s answer for the thread then, when the rule applied
// to it, and rules (2) and (3)'s otherwise. It is unattributed before every remembered epoch, since the state then is no
// longer known (or had no step at all); in an interval a transition folded late leaves unknown; and when an epoch after
// it changed more threads' answers than it keeps, not the thread's among them, while rule (1) may have applied to the
// thread (a model request had named a thread by tid). s.mu must be held.
func (s *Steps) asOf(mono uint64, key []byte) record.Attribution {
	unattributed := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	k := s.nEpochs - 1
	for k >= 0 && s.epochs[(s.headEpoch+k)%maxEpochs].mono > mono {
		k--
	}
	if k < 0 {
		return unattributed
	}
	// The thread's answer at mono is the one the first later epoch that changed it kept, or its answer now when none did.
	var own *ownAnswer
	var none ownAnswer // rule (1) did not apply to the thread
	for i := k + 1; i < s.nEpochs; i++ {
		e := &s.epochs[(s.headEpoch+i)%maxEpochs]
		if e.from <= mono {
			return unattributed // a transition folded after a later one happened by then, and epoch k does not hold it
		}
		if key == nil || own != nil {
			continue
		}
		for j := range e.before {
			if e.before[j].thread == string(key) {
				own = &e.before[j]
				break
			}
		}
		if own == nil && e.all {
			if e.tids {
				return unattributed // it may have changed the thread's answer, and did not keep it
			}
			own = &none // no model request had named its thread by tid, so rule (1) applied to no thread then
		}
	}
	switch {
	case own != nil && own.ok:
		return own.attr
	case own == nil && key != nil:
		if st, ok := s.ownState(string(key)); ok {
			return s.ownAttribution(string(key), st)
		}
	}
	return s.epochs[(s.headEpoch+k)%maxEpochs].attr
}

// openWindow records that the reply on thread, in step, asked for the tool_use id (E29); s.mu must be held. inOrder
// says no model request of the thread was folded after the response the decision follows (stampDecision).
func (s *Steps) openWindow(id, thread string, step int, inOrder bool) {
	if s.windowsLost {
		return
	}
	if _, ok := s.reported[id]; ok {
		// A request already reported its result: the source wrote the reply's decision after the next turn's request
		// (it writes them once it has read the reply's last byte, which the agent may have read first). Opened, the
		// window would stay open for good and claim every later action.
		delete(s.reported, id)
		return
	}
	s.forget(id)
	if len(s.windows)+len(s.unknown) >= MaxToolWindows {
		s.touchHolders() // their window answers go with the windows
		s.windowsLost, s.windows, s.threadWindows, s.unknown, s.threadUnknown = true, nil, nil, nil, nil
		return
	}
	if !inOrder || step < s.unreadBelow {
		// Which reply asked for it is not known (a model request of its thread came after its response), or a request
		// derive did not read may have reported it already (closeWindows): opened, it could stay open for good and claim
		// every later action; left out, its tool may still run while another window looks like the only one.
		s.hold(id, thread)
		return
	}
	if s.windows == nil {
		s.windows, s.threadWindows = map[string]toolWindow{}, map[string][]string{}
	}
	s.windows[id] = toolWindow{thread: thread, step: step}
	s.threadWindows[thread] = append(s.threadWindows[thread], id)
}

// closeWindows closes the windows whose results a model request reported, open or of unknown state, or, for a request
// derive did not read (results nil), makes every open window of the run one of unknown state: such a request may have
// reported any of them, not only its own thread's (the next turn's request can come on another forwarder lane or from
// another thread, and a conversation can go on in another process), and a window left open on a guess would claim every
// later action, while one closed on a guess may still have its tool running when another becomes the only one. A
// decision folded after it, of a reply in a step opened before it, opens its window of unknown state too (unreadBelow).
// s.mu must be held.
func (s *Steps) closeWindows(results *[]string) {
	if results == nil {
		s.touchHolders()
		for id, w := range s.windows {
			s.hold(id, w.thread)
		}
		clear(s.windows)
		clear(s.threadWindows)
		s.unreadBelow = s.next + 1
		return
	}
	for _, id := range *results {
		if w, ok := s.windows[id]; ok {
			s.touch(w.thread)
			s.dropWindow(w.thread, id)
		} else if thread, ok := s.unknown[id]; ok {
			s.touch(thread)
			s.release(id)
		} else if !s.windowsLost {
			s.report(id)
		}
	}
}

// touchHolders touches every thread that holds an open window, whose answers one change makes at once, in the order of
// their names; s.mu must be held. They are a map's keys, and which threads an epoch keeps answers for (the first
// maxTouched, of this transition or of every one folded into the same epoch) must not depend on the order a map is
// walked in: a replay of one ledger answers every late action alike.
func (s *Steps) touchHolders() {
	if s.touchedAll || len(s.threadWindows) == 0 {
		return
	}
	held := make([]string, 0, len(s.threadWindows))
	for thread := range s.threadWindows {
		held = append(held, thread)
	}
	slices.Sort(held)
	for _, thread := range held {
		s.touch(thread)
	}
}

// hold records id's window, of the reply on thread, as one of unknown state; s.mu must be held.
func (s *Steps) hold(id, thread string) {
	if s.unknown == nil {
		s.unknown, s.threadUnknown = map[string]string{}, map[string]int{}
	}
	s.unknown[id] = thread
	s.threadUnknown[thread]++
}

// release forgets id's window of unknown state; s.mu must be held.
func (s *Steps) release(id string) {
	thread := s.unknown[id]
	delete(s.unknown, id)
	if n := s.threadUnknown[thread] - 1; n > 0 {
		s.threadUnknown[thread] = n
	} else {
		delete(s.threadUnknown, thread)
	}
}

// forget drops id's window, open or of unknown state, which a later decision with the same id replaces; s.mu must be
// held.
func (s *Steps) forget(id string) {
	if w, ok := s.windows[id]; ok {
		s.touch(w.thread)
		s.dropWindow(w.thread, id)
	}
	if thread, ok := s.unknown[id]; ok {
		s.touch(thread)
		s.release(id)
	}
}

// MaxUnopenedResults bounds the tool_use ids remembered as reported before their window opened; past it the oldest is
// forgotten, and a decision folded after its report opens its window again.
const MaxUnopenedResults = 4096

// reportRef is one report, in the order reports happened.
type reportRef struct {
	id  string
	seq uint64
}

// report remembers that a request reported id's result while no window of it was open; s.mu must be held.
func (s *Steps) report(id string) {
	if _, ok := s.reported[id]; ok {
		return
	}
	if s.reported == nil {
		s.reported = map[string]uint64{}
	}
	for len(s.reportedOrder) >= MaxUnopenedResults {
		if old := s.reportedOrder[0]; s.reported[old.id] == old.seq {
			delete(s.reported, old.id) // not when a window took it since and a later report made it again
		}
		s.reportedOrder = s.reportedOrder[1:]
	}
	s.reportedSeq++
	s.reported[id] = s.reportedSeq
	s.reportedOrder = append(s.reportedOrder, reportRef{id: id, seq: s.reportedSeq})
}

// dropWindow removes one open window; s.mu must be held.
func (s *Steps) dropWindow(thread, id string) {
	delete(s.windows, id)
	ids := s.threadWindows[thread]
	if i := slices.Index(ids, id); i >= 0 {
		ids = slices.Delete(ids, i, i+1)
	}
	if len(ids) == 0 {
		delete(s.threadWindows, thread)
		return
	}
	s.threadWindows[thread] = ids
}

// byTime is the pure rule of R33–R36 over the run's threads, from the counts Steps keeps rather than a
// snapshot of every thread; s.mu must be held.
//
// Exactly one thread waiting on a model response: the action belongs to that step, likely. No thread
// waiting: the one thread that has a step — the turn whose tools are running — takes it, still likely.
// No thread with a step at all, or several to choose between: unattributed, because a guess between two
// concurrent turns is exactly what a view must never present as fact (R34). An attribution a richer
// method already made is returned unchanged, never lowered to time (R35).
func (s *Steps) byTime(ev *record.Event) record.Attribution {
	if ev != nil && ev.Attr != nil && richerThanTime(ev.Attr.Method) {
		return *ev.Attr
	}
	switch {
	case len(s.inflight) == 1:
		for thread, st := range s.inflight {
			return *record.AttributedByTime(thread, st.Step)
		}
	case len(s.inflight) == 0 && s.stepped == 1:
		return *record.AttributedByTime(s.solo, s.stepOf(s.solo))
	}
	return record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
}

// inOrder reports whether a decision of thread follows a response of the thread folded after its latest model request
// (answered): true for a thread with no state, of which nothing says otherwise. s.mu must be held.
func (s *Steps) inOrder(thread string) bool {
	if st, ok := s.states[thread]; ok {
		return st.answered
	}
	if r, ok := s.retired[thread]; ok {
		return r.answered
	}
	return true
}

// stepOf is a thread's current step, live or retired; 0 when it has none. s.mu must be held.
func (s *Steps) stepOf(thread string) int {
	if st, ok := s.states[thread]; ok {
		return st.Step
	}
	return s.retired[thread].Step
}

// stampDecision fills a decision's step when the parser left it at zero: derive owns the numbering, the
// parser only owns the content. A tool_use decision opens its tool window in the step it is numbered into (R42), when
// it follows a response of its thread folded after the thread's latest model request. A source writes a reply's
// decisions right after its ssl_response, on its thread, but the forwarder writes each declared host's lines through a
// queue of its own while a process's turns to two hosts share its lanes, so another host's request on the same lane can
// come between the two, and a queue can drop the response line: a decision folded after a later model request of its
// thread, or with no response since its latest one, is one whose reply is not known, and so is its window's state.
func (s *Steps) stampDecision(ev *record.Event) {
	var p record.DecisionPayload
	if err := ev.DecodePayload(&p); err != nil {
		return
	}
	// A decision is read out of its own thread's response, so that thread's step is its step; time decides
	// only when the thread has none. By time alone, a response that arrived while another thread's request
	// was in flight gave its decisions the other thread's step.
	thread := Thread(ev)
	s.mu.Lock()
	step := p.Step
	if step == 0 {
		step = s.stepOf(thread)
	}
	if step == 0 {
		step = s.byTime(ev).Step
	}
	if p.ToolUseID != "" && !p.Unparsed && step != 0 {
		s.touch(thread)
		s.openWindow(p.ToolUseID, thread, step, s.inOrder(thread))
		s.transition(ev.MonoNS)
	}
	s.mu.Unlock()
	if step == 0 || p.Step != 0 {
		return
	}
	p.Step = step
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(ev.Payload, &fields); err != nil {
		return
	}
	encoded, err := json.Marshal(p.Step)
	if err != nil {
		return
	}
	fields["step"] = encoded
	if raw, err := json.Marshal(fields); err == nil {
		ev.Payload = raw
	}
}

// richerThanTime reports whether a method already decided more than time can (R35): a tool_use id or a
// thread id, both P1 derivations.
func richerThanTime(method string) bool {
	return method == record.MethodToolID || method == record.MethodTID
}
