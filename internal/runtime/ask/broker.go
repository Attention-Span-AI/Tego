// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

const (
	DefaultTimeout    = 5 * time.Minute
	DefaultMaxPending = 64
	ReasonDenied      = "ask-denied"
	ReasonTimeout     = "ask-timeout"
	ReasonUnavailable = "ask-unavailable"
	// MaxStanding bounds the standing decisions people make in one run. They are made one at a time by a human, so
	// the bound is a safety net, not a quota a run reaches.
	MaxStanding = 256
	// MaxTimeoutStanding bounds the standing refusals timeouts leave in one run (Options.TimeoutStands). They are
	// counted apart from MaxStanding: the agent alone decides how many distinct asks nobody answers, and those must
	// never use up the standing answers a person can still give. Past it a timeout refuses once, as under refuse.
	MaxTimeoutStanding = 256
)

// The errors an exchange ends in are pkg/spec/askproto's, whose texts are on the wire; each is documented there.
var (
	ErrUnavailable     = askproto.ErrUnavailable
	ErrNotPending      = askproto.ErrNotPending
	ErrUnauthorized    = askproto.ErrUnauthorized
	ErrProtocol        = askproto.ErrProtocol
	ErrNotRememberable = askproto.ErrNotRememberable
	ErrStandingFull    = askproto.ErrStandingFull
	ErrStandingBusy    = askproto.ErrStandingBusy
	ErrNoAlternate     = askproto.ErrNoAlternate
	ErrBadAlternate    = askproto.ErrBadAlternate
)

// Peer is the kernel identity of the process which wrote an administrative packet: the pid and uid the kernel gave
// the connection or the packet, and the cgroup and cgroup namespace peer.Identify read and proved for that pid on
// the connection (the socket reads them at the connect and again once the packet is in).
type Peer struct {
	PID int
	UID uint32
	// Cgroup is the peer's unified cgroup path, relative to this process's cgroup namespace root; CgroupNS the inode
	// of its cgroup namespace, 0 when it could not be read (peer.Peer).
	Cgroup   string
	CgroupNS uint64
}

// HoldOpen is the hold of a file-open approval: the open syscall itself is held, whatever the contract's
// ask.hold, which places network asks only (connect, first_write, request), says (ask-4).
const HoldOpen = "open"

// OpRead is the op of a held read-open under fs.ask_read (POC 2026-10-06): the open is held, as HoldOpen says, and
// the op tells the person, and the standing key, that what is asked for is a read. An fs.ask write-open and a
// gate-raised open keep op open.
const OpRead = "read"

// HoldMutation is the hold of a filesystem mutation in an fs.ask scope (ADR 0047): the unlink, rmdir, mkdir, rename,
// symlink or link syscall itself is held, whatever ask.hold says, and the supervisor makes it on the directories it
// pinned once a person approves. Its op is the record's fs op (unlink, mkdir, rename, symlink, link), and a rename's or
// a link's new name, or a symlink's stored target, is Target2.
const HoldMutation = "mutation"

// mutationOps are the ops a HoldMutation request carries: the record's fs ops of the mutations ADR 0047 completes.
var mutationOps = map[string]bool{"unlink": true, "mkdir": true, "rename": true, "symlink": true, "link": true}

// MaxAlternate bounds an alternate's path, PATH_MAX with its terminator (askproto.MaxAlternate).
const MaxAlternate = askproto.MaxAlternate

// Request describes the immutable held operation. AskID is assigned by Broker.
type Request struct {
	Score    *int   `json:"score,omitempty"`
	GateRule string `json:"gate_rule,omitempty"`
	AskID    string `json:"ask_id"`
	Op       string `json:"op"`
	Target   string `json:"target"`
	// Target2 is a held mutation's second name (HoldMutation): a rename's or a link's new name, a symlink's stored
	// target, exactly as the person is shown it. Empty for every other request.
	Target2 string `json:"target2,omitempty"`
	Rule    string `json:"rule"`
	Hold    string `json:"hold"`
	PID     int    `json:"pid"`
	TID     int    `json:"tid"`
	// Alternates, set by the supervisor on a held file open, says whether a person's alternate (a file delivered in
	// place of the target, ADR 0057) passes the open's checks: run before the answer is chosen, so a refused one
	// leaves the request pending and the person is told why. Nil: the request takes no alternate (ErrNoAlternate).
	// A pointer, so a Request stays comparable. Never on the wire.
	Alternates *AlternateCheck `json:"-"`
}

// AlternateCheck is a held open's check of an alternate (Request.Alternates).
type AlternateCheck struct {
	check func(*AlternateFile) (string, error)
}

// NewAlternateCheck wraps check, which must not call the broker, must be bounded, must judge the file by its
// descriptor alone (never by a path) and afresh each time, since the supervisor checks it again when it delivers
// it, and returns the path the supervisor's own view names the file by, which the answer line records.
func NewAlternateCheck(check func(*AlternateFile) (string, error)) *AlternateCheck {
	if check == nil {
		return nil
	}
	return &AlternateCheck{check: check}
}

// Check runs the check; a nil AlternateCheck takes no alternate.
func (c *AlternateCheck) Check(a *AlternateFile) (string, error) {
	if c == nil || c.check == nil {
		return "", ErrNoAlternate
	}
	return c.check(a)
}

type Decision struct {
	AskID    string  `json:"ask_id"`
	Approved bool    `json:"approved"`
	By       string  `json:"by"`
	Reason   string  `json:"reason,omitempty"`
	AfterS   float64 `json:"after_s"`
	// Always marks a decision that set a standing decision ("approve --always") or was taken from one. A
	// decision taken from one has By "standing:<ask_id of the answer that set it>", so the ledger names the
	// human answer behind every automatic allow and deny. A request whose owner cancelled it after its " always"
	// line was recorded comes back refused (ask-unavailable, by "cancelled") with Always still set: the recorded
	// answer stands for later requests although this one's operation was not done.
	Always bool `json:"always,omitempty"`
	// Alternate is the file a person named in place of the target (ADR 0057), by the path the supervisor's check
	// read from its descriptor: the supervisor reopens that descriptor (File), as the agent, and delivers it as the
	// open's result. Approved is false (the operation as asked, the target, was not granted) and Reason is empty
	// (nothing was refused), so a consumer that does not know alternates refuses the operation. Every path that
	// turns a decision into a refusal clears it and closes File.
	Alternate string `json:"alternate,omitempty"`
	// AlternateDev and AlternateIno are the alternate's identity (st_dev, st_ino), fixed when the person named it.
	AlternateDev uint64 `json:"alternate_dev,omitempty"`
	AlternateIno uint64 `json:"alternate_ino,omitempty"`
	// File is the alternate's descriptor, owned by whoever holds the Decision: Request's caller closes it
	// (CloseAlternate). Never on the wire.
	File *AlternateFile `json:"-"`
}

// CloseAlternate closes the decision's alternate descriptor, if any, and forgets it.
func (d *Decision) CloseAlternate() {
	if d.File != nil {
		_ = d.File.Close()
		d.File = nil
	}
}

type Event struct {
	Kind     string
	Request  Request
	Decision Decision
}

// Options callbacks are mandatory. Authorize must reject processes in the
// governed cgroup and its descendants, and in any other run's or adoption's
// (peer.Refuse); UID alone does not establish a human.
// Emit must accept the event or return an error. It must be bounded and
// must not call Request, Answer or Close synchronously on the same broker.
type Options struct {
	UID        uint32
	Timeout    time.Duration
	MaxPending int
	Authorize  func(Peer) error
	Emit       func(Event) error
	// Pending, when set, is told of each held request once it is listed (a person can see and answer it), never of
	// one a standing answer decides. It is called on the requesting goroutine, which holds the agent's operation,
	// so it must not block: the launcher's notice queues and returns (internal/cli asknotice.go, ADR 0122).
	Pending func(Request)
	// TimeoutStands is ask.on_timeout: refuse_always. A held request that times out then leaves a standing refusal
	// for its operation, rule and target, as a person's "deny --always" does (timeoutLocked).
	TimeoutStands bool
}

type pending struct {
	req        Request
	started    time.Time
	ready, won bool
	choice     chan Decision
	done       chan struct{}
	result     Decision
	err        error
	// remember is the standing answer a human's "always" (or a timeout under TimeoutStands) asks for. It is
	// installed only once the answer line saying " always" is in the ledger (installStanding), never when the
	// answer is given.
	remember *standing
}

// Broker owns its socket and bounded pending queue. It never owns a target's descriptor; it holds an alternate's
// (AlternateFile) only while an answer that names one is chosen and recorded, and a standing alternate's until it
// closes.
type Broker struct {
	opts    Options
	mu      sync.Mutex
	closed  bool
	pending map[string]*pending
	server  *server
	// standing holds the "always" answers of this run, by the exact operation, rule and target they were
	// given for. It lives and dies with the broker: nothing is kept across runs.
	standing map[standingKey]standing
	// inflight counts the standing answers between their ask line and their answer line. Like a held request each is
	// an open ask in the ledger, whose reader refuses more than MaxPending at once, so they count against that cap.
	inflight int
}

// standingKey is what a standing decision matches: the operation, the contract rule and the exact target (both
// names of a held mutation that has two), and nothing else. A request that differs in any of them is held anew, so a
// remembered answer never reaches a target, a rule or an operation the human did not see.
type standingKey struct{ op, rule, target, target2 string }

type standing struct {
	approved bool
	// askID is the answer that set it; every later automatic decision names it in By.
	askID string
	// alternate is the file a standing alternate delivers to every later request for its key, by the path the
	// check read, and file its descriptor, owned by the broker until it closes: the same file, by the descriptor
	// the person's command passed, which the supervisor checks anew for each delivery (Decision.Alternate). Every
	// later answer line repeats this path, the one recorded when the person named the file, even after the agent
	// renamed it: the file is dev/ino, and the delivery's fs line names its path then (ADR 0057 D1).
	alternate string
	// reason is the refusal's reason when it is not ReasonDenied: ReasonTimeout for one a timeout left
	// (Options.TimeoutStands), so no later line says a person denied what nobody answered.
	reason   string
	dev, ino uint64
	file     *AlternateFile
}

// timedOut reports whether a timeout left the standing answer (Options.TimeoutStands), which MaxTimeoutStanding
// bounds, rather than a person.
func (s standing) timedOut() bool { return s.reason == ReasonTimeout }

// decision is the answer a standing decision gives the request with ask id id: the human's approval, refusal or
// alternate, By naming the answer that set it. An alternate's decision carries its own duplicate of the standing
// descriptor; one that cannot be made (the broker closed meanwhile) is refused, ask-unavailable.
func (s standing) decision(id string) Decision {
	d := Decision{AskID: id, Approved: s.approved, By: "standing:" + s.askID, Always: true, Alternate: s.alternate, AlternateDev: s.dev, AlternateIno: s.ino}
	if !s.approved && s.alternate == "" {
		d.Reason = ReasonDenied
		if s.reason != "" {
			d.Reason = s.reason
		}
	}
	if s.alternate != "" {
		f, err := s.file.Dup()
		if err != nil {
			return refused(d, ReasonUnavailable)
		}
		d.File = f
	}
	return d
}

// refused turns d into the refusal the broker answers in place of an answer it could not keep: nothing is approved,
// no alternate is delivered (its descriptor is closed), nothing stands.
func refused(d Decision, reason string) Decision {
	d.CloseAlternate()
	d.Approved, d.Reason, d.Always, d.Alternate, d.AlternateDev, d.AlternateIno = false, reason, false, "", 0, 0
	return d
}

// replaced is next in place of d, whose alternate descriptor is closed: a cancellation that overtook an answer.
func replaced(d, next Decision) Decision {
	d.CloseAlternate()
	return next
}

// standingKeyOf is the key a request is remembered under. Only a file open, a held mutation or a TCP connect is: the
// human approved that operation on that target (on both names, for a mutation that has two), and nothing about it
// changes between repeats. A scored gate request
// is decided in the light of its score, and a first_write or request hold is bound to the bytes it carries (a
// later request to the same URL can carry other content), so those are answered once and never remembered.
func standingKeyOf(r Request) (standingKey, bool) {
	if r.Score != nil || r.GateRule != "" || (r.Hold != HoldOpen && r.Hold != HoldMutation && r.Hold != "connect") {
		return standingKey{}, false
	}
	return standingKey{r.Op, r.Rule, r.Target, r.Target2}, true
}

func New(runDir string, opts Options) (*Broker, error) {
	if opts.Authorize == nil || opts.Emit == nil {
		return nil, fmt.Errorf("%w: authorization and ledger callbacks required", ErrUnavailable)
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxPending == 0 {
		opts.MaxPending = DefaultMaxPending
	}
	if opts.Timeout <= 0 || opts.MaxPending < 1 || opts.MaxPending > DefaultMaxPending {
		return nil, fmt.Errorf("%w: invalid bounds", ErrUnavailable)
	}
	b := &Broker{opts: opts, pending: make(map[string]*pending), standing: make(map[standingKey]standing)}
	s, err := newServer(runDir, b)
	if err != nil {
		return nil, err
	}
	b.server = s
	return b, nil
}

// validRequest bounds a request and checks its hold: one of ask.hold's network holds, HoldOpen, which a
// file open, and only a file open (op open, or read for an fs.ask_read hold), carries, or HoldMutation, which only a
// mutation op carries, and only it may name a second target. Only a file open may take an alternate.
func validRequest(r Request) bool {
	fileOp := r.Op == "open" || r.Op == OpRead
	if (r.Hold == HoldMutation) != mutationOps[r.Op] || (r.Target2 != "" && r.Hold != HoldMutation) || len(r.Target2) > 4096 || !utf8.ValidString(r.Target2) {
		return false
	}
	return (r.Score == nil || *r.Score >= 0 && *r.Score <= 100) && len(r.GateRule) <= 1024 && utf8.ValidString(r.GateRule) && r.AskID == "" && r.PID > 0 && r.TID > 0 && len(r.Op) > 0 && len(r.Op) <= 64 && len(r.Target) > 0 && len(r.Target) <= 4096 && len(r.Rule) <= 1024 && utf8.ValidString(r.Op) && utf8.ValidString(r.Target) && utf8.ValidString(r.Rule) && (r.Hold == "connect" || r.Hold == "first_write" || r.Hold == "request" || r.Hold == HoldOpen || r.Hold == HoldMutation) && (r.Hold == HoldOpen) == fileOp && (r.Alternates == nil || r.Hold == HoldOpen)
}

// ValidAlternate reports whether p can be an alternate at all, before any file is looked at
// (askproto.ValidAlternate, whose doc is the rule).
func ValidAlternate(p string) bool { return askproto.ValidAlternate(p) }

func cancelledDecision(id string, err error) Decision {
	d := Decision{AskID: id, Reason: ReasonUnavailable, By: "cancelled"}
	if errors.Is(err, context.DeadlineExceeded) {
		d.Reason, d.By = ReasonTimeout, "timeout"
	}
	return d
}

// Request publishes a held operation after its ask event has been accepted.
// The answer event is accepted before any approval is returned. All competing
// answers, cancellation and timeout select exactly one terminal decision.
func (b *Broker) Request(ctx context.Context, req Request) (Decision, error) {
	if req.Score != nil {
		score := *req.Score
		req.Score = &score
	}
	if !validRequest(req) {
		return Decision{Reason: ReasonUnavailable}, fmt.Errorf("%w: invalid request", ErrProtocol)
	}
	if err := ctx.Err(); err != nil {
		return cancelledDecision("", err), err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Decision{Reason: ReasonUnavailable}, err
	}
	req.AskID = "q-" + hex.EncodeToString(id[:])
	p := &pending{req: req, started: time.Now(), choice: make(chan Decision, 1), done: make(chan struct{})}
	b.mu.Lock()
	if b.closed || len(b.pending)+b.inflight >= b.opts.MaxPending {
		b.mu.Unlock()
		return Decision{Reason: ReasonUnavailable}, ErrUnavailable
	}
	if s, ok := b.standingLocked(req); ok {
		// Looked up under the lock that registers a held request, so an "always" answer either already stands
		// here, or finds this request pending and answers it too: none is held past it.
		b.inflight++
		b.mu.Unlock()
		defer func() { b.mu.Lock(); b.inflight--; b.mu.Unlock() }()
		return b.applyStanding(ctx, req, s)
	}
	b.pending[req.AskID] = p
	b.mu.Unlock()
	if err := b.opts.Emit(Event{Kind: "ask", Request: req}); err != nil {
		b.finish(p, Decision{AskID: req.AskID, Reason: ReasonUnavailable}, err)
		return p.result, err
	}
	b.mu.Lock()
	p.ready = true
	closed := b.closed
	if closed {
		b.chooseLocked(p, Decision{AskID: req.AskID, Reason: ReasonUnavailable, By: "shutdown"})
	}
	b.mu.Unlock()
	timer := time.NewTimer(b.opts.Timeout)
	defer timer.Stop()
	if !closed && b.opts.Pending != nil {
		b.opts.Pending(req)
	}
	var result Decision
	select {
	case result = <-p.choice:
	case <-ctx.Done():
		b.choose(p, cancelledDecision(req.AskID, ctx.Err()))
		result = <-p.choice
	case <-timer.C:
		b.mu.Lock()
		b.timeoutLocked(p)
		b.mu.Unlock()
		result = <-p.choice
	}
	// A winning approval cannot resurrect work after its owner cancelled it.
	b.mu.Lock()
	closed = b.closed
	b.mu.Unlock()
	if closed {
		result = refused(result, ReasonUnavailable)
		result.By = "shutdown"
	} else if cause := ctx.Err(); cause != nil {
		result = replaced(result, cancelledDecision(req.AskID, cause))
	}
	result.AfterS = time.Since(p.started).Seconds()
	err := b.opts.Emit(Event{Kind: "answer", Request: req, Decision: result})
	// What the line says is what stands: an answer whose line ends in " always" was recorded as standing.
	recordedAlways := err == nil && result.Always
	// A recorded standing alternate keeps the descriptor its line named, since a cancellation below closes this
	// request's own (replaced) before installStanding runs.
	var standFile *AlternateFile
	if recordedAlways && p.remember != nil && p.remember.alternate != "" {
		standFile, _ = result.File.Dup()
	}
	if err != nil {
		// An unrecorded answer grants nothing and delivers no alternate.
		result = refused(result, ReasonUnavailable)
	}
	b.mu.Lock()
	closed = b.closed
	b.mu.Unlock()
	if closed {
		result = refused(result, ReasonUnavailable)
	} else if cause := ctx.Err(); cause != nil && err == nil {
		after := result.AfterS
		result = replaced(result, cancelledDecision(req.AskID, cause))
		result.AfterS = after
	}
	// An "always" (a person's, or a timeout's under TimeoutStands) takes effect only now that its answer line is in
	// the ledger: an answer cancelled, closed or refused before its line installs nothing, its line not saying
	// " always", and a later request that cited it could never be traced to a recorded answer. Once the line says
	// " always" it is installed from that line, not from what this one request became after it: an owner
	// cancelled between the line and here (a held thread killed as its answer was written) loses this request's
	// operation, not the recorded answer, which a later identical request must find standing, or the ledger would
	// name a standing answer that never stood. That holds for a standing alternate too: its
	// descriptor is the one the recorded answer named (standFile, kept before a cancellation closed this request's
	// own), never nothing. Only a broker closed meanwhile installs nothing, as it answers no later request. Always
	// on the returned decision says whether it stands, so the person's CLI can say so even for a request that was
	// itself cancelled. A request answered from another's standing answer (remember nil) keeps the Always it was
	// given.
	if p.remember != nil {
		result.Always = recordedAlways && b.installStanding(p, standFile)
	}
	_ = standFile.Close()
	b.finish(p, result, err)
	return result, err
}

// timeoutLocked chooses the timeout for p, unless an answer won first. Under Options.TimeoutStands the timeout also
// asks for a standing refusal of p's key, as a person's "deny --always" does, and on the same terms: it is installed
// only once the timeout's answer line is recorded (installStanding), never for a request that cannot be remembered
// (a scored gate request, a first_write or request hold), never past MaxTimeoutStanding (a bound of its own, so
// timeouts never use up a person's MaxStanding), and never while a person's
// "always" for the same key is being recorded, which then stands instead (ErrStandingBusy's rule, from the other
// side). A timeout that cannot stand refuses once, as it always has. b.mu is held.
func (b *Broker) timeoutLocked(p *pending) {
	if p.won {
		return
	}
	d := Decision{AskID: p.req.AskID, Reason: ReasonTimeout, By: "timeout"}
	if b.opts.TimeoutStands && b.mayStandLocked(p, true) {
		p.remember = &standing{askID: p.req.AskID, reason: ReasonTimeout}
		// By ends in " always" as a person's answer that sets a standing decision does, so the timeout's line says
		// that later refusals cite it.
		d.Always = true
		d.By += " always"
	}
	b.chooseLocked(p, d)
}

// mayStandLocked reports whether p's answer, a timeout's when timedOut, can be remembered now: p's request has a
// standing key, the run's standing answers of that kind have room for it (roomLocked), and no other "always" for the
// key is being recorded. b.mu is held.
func (b *Broker) mayStandLocked(p *pending, timedOut bool) bool {
	key, ok := standingKeyOf(p.req)
	if !ok || !b.roomLocked(key, timedOut, p) {
		return false
	}
	for _, q := range b.pending {
		if q == p || q.remember == nil {
			continue
		}
		if k, ok := standingKeyOf(q.req); ok && k == key {
			return false
		}
	}
	return true
}

// roomLocked reports whether a standing answer for key, a timeout's when timedOut, fits its bound: MaxStanding for a
// person's, MaxTimeoutStanding for a timeout's. It counts what stands and what is reserved: every pending request
// other than except whose "always" was chosen (remember) and is still being recorded, for a key that does not stand
// yet. Reserving the slot when the answer is chosen is what lets an answer line say "always" truthfully: the check
// at installStanding then cannot fail for want of room, so no line says "always" for an answer that stood for
// nothing. A key that already stands as the same kind is replaced and takes no new slot. b.mu is held.
func (b *Broker) roomLocked(key standingKey, timedOut bool, except *pending) bool {
	if s, had := b.standing[key]; had && s.timedOut() == timedOut {
		return true
	}
	n := 0
	for _, s := range b.standing {
		if s.timedOut() == timedOut {
			n++
		}
	}
	for _, q := range b.pending {
		if q == except || q.remember == nil || q.remember.timedOut() != timedOut {
			continue
		}
		if k, ok := standingKeyOf(q.req); ok && k != key {
			if _, had := b.standing[k]; !had {
				n++
			}
		}
	}
	limit := MaxStanding
	if timedOut {
		limit = MaxTimeoutStanding
	}
	return n < limit
}

// installStanding makes p's "always" answer stand, and answers the requests already held for the same key the same
// way. It reports false when it could not (the broker closed), in which case the answer applies once. Called after
// the human's answer line is recorded, so every line that cites it follows it. Room was reserved when the answer was
// chosen (roomLocked); the bound is checked again only as a guard. A standing alternate keeps its own duplicate of
// file, the recorded answer's descriptor, until the broker closes.
func (b *Broker) installStanding(p *pending, file *AlternateFile) bool {
	s := *p.remember
	if s.alternate != "" {
		f, err := file.Dup()
		if err != nil {
			return false
		}
		s.file = f
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key, ok := standingKeyOf(p.req)
	if b.closed || !ok || !b.roomLocked(key, s.timedOut(), p) {
		_ = s.file.Close()
		return false
	}
	old, had := b.standing[key]
	if had {
		_ = old.file.Close()
	}
	p.remember = &s
	b.standing[key] = s
	for _, q := range b.pending {
		// A request registered but not yet published (its ask line is being written) is answered too: it takes this
		// decision from its channel once the ask line is out, so the pair stays whole.
		if q == p || q.won {
			continue
		}
		if k, ok := standingKeyOf(q.req); ok && k == key {
			b.chooseLocked(q, p.remember.decision(q.req.AskID))
		}
	}
	return true
}

// standingLocked reports the standing decision that covers req, if any. b.mu is held.
func (b *Broker) standingLocked(req Request) (standing, bool) {
	key, ok := standingKeyOf(req)
	if !ok || b.closed {
		return standing{}, false
	}
	s, ok := b.standing[key]
	return s, ok
}

// applyStanding answers req from a standing decision without holding it, and records it as the same ask and
// answer pair a held request leaves, so the ledger never shows an unrecorded grant or refusal: the answer
// line's By is "standing:<ask_id>". It fails closed as Request does: a ledger that refuses either line, a
// broker closed meanwhile, or an owner that cancelled meanwhile, refuses the operation (a winning approval
// cannot resurrect work after its owner cancelled it).
func (b *Broker) applyStanding(ctx context.Context, req Request, s standing) (Decision, error) {
	if !b.Available() {
		return Decision{AskID: req.AskID, Reason: ReasonUnavailable, By: "shutdown"}, ErrUnavailable
	}
	if err := b.opts.Emit(Event{Kind: "ask", Request: req}); err != nil {
		return Decision{AskID: req.AskID, Reason: ReasonUnavailable}, err
	}
	d := s.decision(req.AskID)
	if cause := ctx.Err(); cause != nil {
		d = replaced(d, cancelledDecision(req.AskID, cause)) // the line records the cancellation, not a grant
	}
	if err := b.opts.Emit(Event{Kind: "answer", Request: req, Decision: d}); err != nil {
		return refused(d, ReasonUnavailable), err
	}
	if !b.Available() {
		d = refused(d, ReasonUnavailable)
		d.By = "shutdown"
	} else if cause := ctx.Err(); cause != nil {
		d = replaced(d, cancelledDecision(req.AskID, cause))
	}
	return d, nil
}

func (b *Broker) finish(p *pending, result Decision, err error) {
	b.mu.Lock()
	delete(b.pending, p.req.AskID)
	p.result, p.err = result, err
	close(p.done)
	b.mu.Unlock()
}

func (b *Broker) chooseLocked(p *pending, d Decision) bool {
	if p.won {
		return false
	}
	p.won = true
	p.choice <- d
	return true
}

func (b *Broker) choose(p *pending, d Decision) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.chooseLocked(p, d)
}

// answer chooses a person's answer for the pending request id: approve, deny, or, with alternate set (and approve
// false), the file, by the descriptor the person's command passed, that the supervisor delivers in place of the
// target. An alternate is first put to the request's own check (Request.Alternates), outside the lock since it
// opens the file as the agent; one it refuses, or a request that takes none, leaves the request pending. The
// caller keeps alternate; the chosen decision holds its own duplicate.
func (b *Broker) answer(ctx context.Context, id string, approve, always bool, alternate *AlternateFile, peer Peer) (Decision, error) {
	resolved := ""
	if alternate != nil {
		if approve || !ValidAlternate(alternate.Named) {
			return Decision{}, ErrProtocol
		}
		b.mu.Lock()
		p := b.pending[id]
		if b.closed || p == nil || !p.ready || p.won {
			b.mu.Unlock()
			return Decision{}, ErrNotPending
		}
		check := p.req.Alternates
		hold := p.req.Hold
		b.mu.Unlock()
		if check == nil || hold != HoldOpen {
			return Decision{}, ErrNoAlternate
		}
		var err error
		if resolved, err = check.Check(alternate); err != nil {
			return Decision{}, fmt.Errorf("%w: %v", ErrBadAlternate, err)
		}
		if !ValidAlternate(resolved) {
			return Decision{}, fmt.Errorf("%w: the supervisor names the file by %q, which a person cannot be shown", ErrBadAlternate, resolved)
		}
	}
	b.mu.Lock()
	p := b.pending[id]
	if b.closed || p == nil || !p.ready || p.won {
		b.mu.Unlock()
		return Decision{}, ErrNotPending
	}
	d := Decision{AskID: id, Approved: approve, By: fmt.Sprintf("uid:%d pid:%d", peer.UID, peer.PID)}
	if alternate != nil {
		d.Alternate, d.AlternateDev, d.AlternateIno = resolved, alternate.Dev, alternate.Ino
	}
	if !approve && alternate == nil {
		d.Reason = ReasonDenied
	}
	if always {
		key, ok := standingKeyOf(p.req)
		if !ok {
			b.mu.Unlock()
			return Decision{}, ErrNotRememberable
		}
		if !b.roomLocked(key, false, p) {
			b.mu.Unlock()
			return Decision{}, ErrStandingFull
		}
		// Two "always" answers for one key cannot both stand: the one chosen first is still being recorded (its
		// request stays in pending until installStanding has run), and the later would overwrite it or be
		// overwritten, with the person told the opposite of what stands.
		for _, q := range b.pending {
			if q == p || q.remember == nil {
				continue
			}
			if k, ok := standingKeyOf(q.req); ok && k == key {
				b.mu.Unlock()
				return Decision{}, ErrStandingBusy
			}
		}
		// Only the intent is kept here: the standing answer is installed by Request once this answer's line is in the
		// ledger and was not replaced by a cancellation, a shutdown or a refusal (installStanding).
		p.remember = &standing{approved: approve, askID: id, alternate: d.Alternate, dev: d.AlternateDev, ino: d.AlternateIno}
		d.Always = true
		d.By += " always"
	}
	if alternate != nil {
		f, err := alternate.Dup()
		if err != nil {
			p.remember = nil
			b.mu.Unlock()
			return Decision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		d.File = f
	}
	b.chooseLocked(p, d)
	b.mu.Unlock()
	select {
	case <-p.done:
		return p.result, p.err
	case <-ctx.Done():
		// A decision already taken is what the person is told, not the server's closing after it.
		select {
		case <-p.done:
			return p.result, p.err
		default:
		}
		return Decision{}, ctx.Err()
	}
}

func (b *Broker) authorize(p Peer) error {
	if p.PID <= 0 || (p.UID != b.opts.UID && p.UID != 0) {
		return ErrUnauthorized
	}
	if err := b.opts.Authorize(p); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

func (b *Broker) Close() error {
	b.shutdown()
	return b.server.close()
}

// Available reports whether the live broker still accepts new held operations.
func (b *Broker) Available() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.closed
}

// Waiting reports whether a published ask awaits its human: its ask line was
// accepted and no answer, timeout or cancellation has been chosen yet.
func (b *Broker) Waiting() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.pending {
		if p.ready && !p.won {
			return true
		}
	}
	return false
}

func (b *Broker) shutdown() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		for _, p := range b.pending {
			b.chooseLocked(p, Decision{AskID: p.req.AskID, Reason: ReasonUnavailable, By: "shutdown"})
		}
		// A standing alternate's descriptor dies with the run's broker; a decision already taken from it holds a
		// duplicate of its own.
		for k, s := range b.standing {
			_ = s.file.Close()
			s.file = nil
			b.standing[k] = s
		}
	}
	b.mu.Unlock()
}

// SocketName is relative to the run's ledger directory.
const SocketName = askproto.SocketName

// Summary is bounded for list replies, and marks each value it cut; Detail returns the full target and rule. Both
// carry the target in its ledger form.
type Summary struct {
	Request
	TargetTruncated bool `json:"target_truncated,omitempty"`
	RuleTruncated   bool `json:"rule_truncated,omitempty"`
}

// shown is req as the socket shows it to every client, list and detail alike: its target in the ledger form the ask
// line records (askclient.LedgerTarget), never the raw target the supervisor holds, whose request path and query may
// carry a credential (record-ledger R9a). Only an http_request target differs.
func shown(req Request) Request {
	req.Target = askclient.LedgerTarget(req.Op, req.Target)
	return req
}

func (b *Broker) list() []Summary {
	b.mu.Lock()
	defer b.mu.Unlock()
	items := make([]Summary, 0, len(b.pending))
	for _, p := range b.pending {
		if !p.ready || p.won {
			continue
		}
		s := Summary{Request: shown(p.req)}
		if len(s.Target) > askproto.MaxSummaryTarget {
			s.Target = utf8Prefix(s.Target, askproto.MaxSummaryTarget)
			s.TargetTruncated = true
		}
		if len(s.Target2) > askproto.MaxSummaryTarget {
			s.Target2 = utf8Prefix(s.Target2, askproto.MaxSummaryTarget)
			s.TargetTruncated = true
		}
		if len(s.Rule) > askproto.MaxSummaryRule {
			s.Rule = utf8Prefix(s.Rule, askproto.MaxSummaryRule)
			s.RuleTruncated = true
		}
		items = append(items, s)
	}
	return items
}

func utf8Prefix(s string, n int) string {
	for n > 0 && !utf8.ValidString(s[:n]) {
		n--
	}
	return s[:n]
}

func (b *Broker) detail(id string) (Request, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.pending[id]
	if p == nil || !p.ready || p.won {
		return Request{}, ErrNotPending
	}
	return shown(p.req), nil
}

func validID(id string) bool { return askproto.ValidID(id) }

// ValidID validates the local broker identifier before a CLI reads account state.
func ValidID(id string) bool { return validID(id) }
