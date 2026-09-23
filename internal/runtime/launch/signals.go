// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Signaler delivers a signal to the agent's main process; *Child implements it through its pidfd.
type Signaler interface {
	Signal(sig syscall.Signal) error
}

// Killer ends the whole run tree; the escalation target of stop_grace (R9: escalate = cgroup.kill).
type Killer interface {
	Kill() error
}

// DefaultDoubleInterrupt is the window in which a second SIGINT escalates immediately (§6).
const DefaultDoubleInterrupt = 2 * time.Second

// SignalPolicy configures the launcher's signal rules (ARCHITECTURE.md §6, RUN-IDENTITY.md Signals, R9).
type SignalPolicy struct {
	// StopGrace is Machine.StopGrace: the time between the first stop signal and cgroup.kill. Required.
	StopGrace time.Duration
	// StdinIsTTY says the terminal already delivered SIGINT/SIGQUIT to the shared process group, so they
	// are not re-sent (sys.IsTerminal(0)).
	StdinIsTTY bool
	// DoubleInterrupt is the second-SIGINT escalation window; 0 means DefaultDoubleInterrupt.
	DoubleInterrupt time.Duration
	// StopRequested reports whether a `tego stop` marker (stop.request) exists; consulted when a stop
	// signal arrives so the run ends with reason=stopped instead of reason=signal. nil means never.
	StopRequested func() bool
	// RequestedGrace returns the grace `tego stop --grace` wrote into that marker, or 0 when it wrote
	// none or the marker holds no valid positive duration (R9, limits-check-doctor-cli.md R29). nil
	// means never. See Handle for when it replaces StopGrace.
	RequestedGrace func() time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// SignalHandler forwards signals to the agent and owns the stop_grace timer for one run.
type SignalHandler struct {
	child  Signaler
	killer Killer
	policy SignalPolicy

	// escalating joins the stop_grace timer's goroutine with Run, so R9's escalation is a member of the
	// run's worker set and not a fire-and-forget AfterFunc (§9 "Goroutine ownership"): runtime.Run reads
	// Outcome() for run_end and closes the run cgroup's directory fd as soon as that set is joined.
	escalating sync.WaitGroup
	// killFailed hands a failed cgroup.kill straight to Run. The tree is still alive after one, so the run
	// has to end on it rather than wait in Child.Wait for processes nothing is going to kill (§7).
	killFailed chan error

	mu        sync.Mutex
	outcome   Outcome
	lastInt   time.Time
	timer     *time.Timer
	stopped   bool // Run has returned: no new stop_grace timer may be armed behind the join
	killErr   error
	forwarded map[syscall.Signal]int
}

// NewSignalHandler builds a handler; policy.StopGrace must be positive.
func NewSignalHandler(child Signaler, killer Killer, policy SignalPolicy) (*SignalHandler, error) {
	if policy.StopGrace <= 0 {
		return nil, fmt.Errorf("launch: SignalPolicy.StopGrace must be positive, got %v", policy.StopGrace)
	}
	if policy.DoubleInterrupt == 0 {
		policy.DoubleInterrupt = DefaultDoubleInterrupt
	}
	if policy.Now == nil {
		policy.Now = time.Now
	}
	if child == nil || killer == nil {
		return nil, errors.New("launch: SignalHandler needs a Signaler and a Killer")
	}
	return &SignalHandler{child: child, killer: killer, policy: policy, killFailed: make(chan error, 1),
		forwarded: map[syscall.Signal]int{}}, nil
}

// HandledSignals is the set the launcher subscribes to (less a SIGHUP it inherited as ignored, see subscribed):
// everything forwarded by rule plus the stop_grace triggers.
func HandledSignals() []os.Signal {
	seen := map[syscall.Signal]bool{}
	var out []os.Signal
	add := func(sigs []syscall.Signal) {
		for _, s := range sigs {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	add(identity.ForwardAlways())
	add(identity.ForwardWhenNotTTY())
	add(identity.StopGraceTriggers())
	return out
}

// jobControl are the stop signals a terminal delivers to its foreground process group: SIGTSTP for Ctrl-Z,
// SIGTTIN and SIGTTOU for a read or (under TOSTOP) a write from a background one.
var jobControl = []os.Signal{syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU}

var (
	holdOnce sync.Once
	held     []int
)

// HoldJobControl keeps this process running through a terminal's job-control stops, for a launcher whose
// enforcement handle owns a loop the host waits on (api.Listener: tier 2's fanotify listener, E40). A
// stopped launcher answers nothing its permission group is sent and keeps its marks, so every open and exec
// on the marked mount of / waits until it continues — Ctrl-Z on `sudo tego run --tier cgroup` stopped the
// host, not only the run. The three are set to SIG_IGN, process-wide and once: ignored, not caught, because
// a caught SIGTTIN or SIGTTOU restarts the tty read or write that raised it (tty_check_change answers
// -ERESTARTSYS and signals the whole process group again), so a launcher writing to its terminal from a
// background group would spin, while an ignored SIGTTOU lets the write through and an ignored SIGTTIN fails
// the read with EIO. Ctrl-Z still stops the agent, which shares the process group and gets its own copy.
//
// An ignored disposition survives execve, where a caught one reverts to the default, so it would reach the
// child stage and then the agent, and the agent would no longer stop on Ctrl-Z. The result is therefore the
// signals the child stage resets to SIG_DFL before it execs the agent (wireSpec.ResetSignals): the ones
// that were not already ignored when this process started, whose ignored disposition the agent inherits as
// it would have without tego. SIGSTOP, a debugger and the cgroup freezer cannot be ignored; they stay E40's
// residual until the decisions leave a stoppable process (tier 3).
func HoldJobControl() []int {
	holdOnce.Do(func() {
		for _, s := range jobControl {
			if !signal.Ignored(s) {
				held = append(held, int(s.(syscall.Signal)))
			}
		}
		signal.Ignore(jobControl...)
	})
	return append([]int(nil), held...)
}

// Notify subscribes to subscribed() and returns the channel and the unsubscribe function.
func Notify() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, subscribed()...)
	return ch, func() { signal.Stop(ch) }
}

// subscribed is HandledSignals less a SIGHUP this process inherited as ignored. nohup ignores SIGHUP
// before it execs tego; subscribing to it anyway would replace that with a handler, so the hangup started
// stop_grace and ended the run (129), and the agent, which inherits an ignored disposition across execve but
// not a caught one, would lose nohup's protection too. Left ignored, the hangup reaches neither, as with any
// command nohup runs. Only SIGHUP: SIGTERM is how `tego stop` ends a run, and SIGINT and SIGQUIT come from
// a terminal a nohup'd run is not reading. signal.Ignored stays true until something subscribes, so a
// second call (the runtime's own when the caller passed none) sees the same answer.
func subscribed() []os.Signal {
	all := HandledSignals()
	if !signal.Ignored(syscall.SIGHUP) {
		return all
	}
	out := all[:0]
	for _, s := range all {
		if s != syscall.SIGHUP {
			out = append(out, s)
		}
	}
	return out
}

// Run consumes signals until ctx is done, then joins the stop_grace timer and returns. It is the run's
// signal goroutine (runtime.Run step 11) and belongs in the caller's errgroup.
//
// A failed cgroup.kill is returned, never swallowed (§7, the rule limits.Watcher already follows for its own
// kill): the escalation did not happen, so the run must end on the group's error path — which retries the
// kill and writes a run_end — instead of blocking forever on a tree that is still running.
func (h *SignalHandler) Run(ctx context.Context, signals <-chan os.Signal) (err error) {
	defer func() {
		h.stopTimer()
		if err == nil {
			err = h.KillError() // an escalation that failed while Run was already on its way out
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case kerr := <-h.killFailed:
			return kerr
		case s, ok := <-signals:
			if !ok {
				return nil
			}
			sig, isSig := s.(syscall.Signal)
			if !isSig {
				continue
			}
			h.Handle(sig)
		}
	}
}

// Handle applies the rules to one delivered signal: forward when identity.Forwardable says so (SIGINT and
// SIGQUIT only when stdin is not a terminal); a stop_grace trigger starts the timer if none runs and
// records the first such signal; a second SIGINT within the double-interrupt window escalates at once.
//
// The timer is armed once, by the first trigger, and never restarted or extended by a later one: a
// process that can signal the launcher could otherwise postpone the escalation for as long as it kept
// sending SIGTERM. Its length is StopGrace, except when that first trigger is the SIGTERM of a
// `tego stop` that asked for its own --grace (a marker present, RequestedGrace positive): then it is
// the requested grace, longer or shorter. Only SIGTERM carries it because SIGTERM is what `tego stop`
// delivers; a SIGINT or SIGHUP that happens to find a marker is not that request. The requested grace
// postpones nothing but this escalation — a second SIGINT still escalates at once, and the run's own
// limits (wall, stall_after) still end it — and stop_grace is itself a setting the same user can raise
// in ~/.tego/config.yaml, so honouring a longer one hands the requester nothing they did not have.
func (h *SignalHandler) Handle(sig syscall.Signal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if identity.Forwardable(sig, h.policy.StdinIsTTY) {
		if err := h.child.Signal(sig); err == nil || errors.Is(err, syscall.ESRCH) {
			h.forwarded[sig]++
		}
	}
	if !identity.StartsStopGrace(sig) {
		return
	}
	now := h.policy.Now()
	if h.outcome.Signal == 0 {
		h.outcome.Signal = sig
		if h.policy.StopRequested != nil && h.policy.StopRequested() {
			h.outcome.Stopped = true
		}
	}
	if sig == syscall.SIGINT {
		if !h.lastInt.IsZero() && now.Sub(h.lastInt) <= h.policy.DoubleInterrupt {
			h.escalateLocked()
			return
		}
		h.lastInt = now
	}
	if h.timer == nil && !h.stopped {
		// Add pairs with escalateFromTimer's Done (or stopTimer's, when Stop wins the race), so the timer
		// goroutine is joined before Run returns.
		h.escalating.Add(1)
		h.timer = time.AfterFunc(h.graceFor(sig), h.escalateFromTimer)
	}
}

// graceFor is the stop_grace the timer armed by sig runs for (see Handle). Called with h.mu held.
func (h *SignalHandler) graceFor(sig syscall.Signal) time.Duration {
	if sig != syscall.SIGTERM || !h.outcome.Stopped || h.policy.RequestedGrace == nil {
		return h.policy.StopGrace
	}
	if g := h.policy.RequestedGrace(); g > 0 {
		return g
	}
	return h.policy.StopGrace
}

// escalateFromTimer is the AfterFunc body; it releases stopTimer's join however the escalation went.
func (h *SignalHandler) escalateFromTimer() {
	defer h.escalating.Done()
	h.Escalate()
}

// Escalate writes cgroup.kill once (R9's escalate); once that write succeeded, later calls are no-ops. Safe
// from the timer goroutine.
func (h *SignalHandler) Escalate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.escalateLocked()
}

func (h *SignalHandler) escalateLocked() {
	if h.outcome.Escalated {
		return
	}
	if err := h.killer.Kill(); err != nil {
		// Outcome.Escalated asserts that cgroup.kill *was written*, and run_end publishes it: a write that
		// failed must not be recorded as a completed escalation, so it stays false. No later signal retries
		// the kill: the error goes to killFailed, Run returns it and stops handling signals, and the group's
		// error path retries the kill the tree still needs and writes run_end (see Run).
		h.killErr = err
		select {
		case h.killFailed <- err:
		default: // Run already holds the first failure; that is the one that ends the run.
		}
		return
	}
	h.killErr = nil
	h.outcome.Escalated = true
}

// stopTimer stops the stop_grace timer and waits for an escalation already in flight, so nothing is still
// writing cgroup.kill once Run has returned (§9 "Goroutine ownership"). It must not hold h.mu across the
// join: escalateLocked takes it.
func (h *SignalHandler) stopTimer() {
	h.mu.Lock()
	t := h.timer
	h.timer, h.stopped = nil, true
	h.mu.Unlock()
	if t != nil && t.Stop() {
		h.escalating.Done() // stopped before it fired, so the AfterFunc body will never run
	}
	h.escalating.Wait()
}

// Outcome returns what was decided so far: the first stop signal, whether cgroup.kill was written, and
// whether the stop was a `tego stop`.
func (h *SignalHandler) Outcome() Outcome {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.outcome
}

// KillError returns the last failed cgroup.kill write: nil when no escalation was attempted or the write
// succeeded. Run returns it, so a caller normally learns of the failure from the worker group.
func (h *SignalHandler) KillError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.killErr
}

// Forwarded reports how many times sig was forwarded to the child.
func (h *SignalHandler) Forwarded(sig syscall.Signal) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.forwarded[sig]
}
