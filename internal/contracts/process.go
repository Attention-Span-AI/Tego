// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// HelperCommand is the private entry point dispatched before normal command setup.
const HelperCommand = "__contracts-check"

const maxExchangeBytes = 128 << 20

// The kernel reservation counts active and abandoned workers across commands.
// Thirty-two permits sixteen concurrent healthy commands with equal headroom;
// it still caps abandoned workers when a mount never answers.
const helperLimit = 32

// StartTimeout bounds everything before a location is asked: waiting for a free helper slot (a closed healthy
// worker needs only scheduling time to release its lease), starting the helper, and its report that it is alive and
// about to touch the location (the ready frame). It is separate from CheckTimeout, which only a helper that has said
// it is ready can use up: a machine too busy to start a process must never read as a location that does not answer.
// 30 s, times raceScale in a race build. A stuck mount costs at most StartTimeout plus CheckTimeout, never a hang. A
// location on this computer's own disk (location.go) whose helper is in uninterruptible sleep is waited for longer: up
// to localCap (30 s) of location time, so at most StartTimeout plus localCap (60 s) for a caller with no request scope
// of its own (the command line), and no more than the request's bound (25 s in all, start-up included) in a dashboard
// request. The start-up part is spent only on a machine too busy to start a process; the usual cost is the location's.
const StartTimeout = 30 * time.Second * raceScale

// startTimeout is StartTimeout, a variable so a test with a synthetic pool can end its slot wait early.
var startTimeout = StartTimeout

// personHelperReserve is how many of the helperLimit slots only a request not marked governed may take
// (WithGovernedCaller): a governed program's requests share the rest, so a burst of them, or their workers'
// slow exits on a busy machine, can never use up what a person's own check needs. The bound on all is unchanged.
const personHelperReserve = 4

// helperReserve is the reserve of a bound of limit slots: personHelperReserve, scaled down to limit/8 for a smaller
// bound (a test's pool of 4 reserves none). The local governed bound and the kernel names a governed request may try
// both derive from it, so they never disagree.
func helperReserve(limit int) int { return min(personHelperReserve, limit/8) }

// helperPools are the local worker bounds for limit slots: all workers, and those of governed requests inside it.
func helperPools(limit int) (all, governed chan struct{}) {
	return make(chan struct{}, limit), make(chan struct{}, limit-helperReserve(limit))
}

// processWorkers bounds this process's helper workers; governedWorkers bounds those of governed requests inside it.
// A test swaps both together with helperPools.
var processWorkers, governedWorkers = helperPools(helperLimit)

type governedCallerKey struct{}

// WithGovernedCaller marks ctx's helper requests as made for a caller that may be a governed program: governed
// says whether it is, called at most once, when a request of ctx first needs a helper slot; true also when it
// cannot tell. Such a request never takes the personHelperReserve slots; it is otherwise answered as before.
func WithGovernedCaller(ctx context.Context, governed func() bool) context.Context {
	return context.WithValue(ctx, governedCallerKey{}, sync.OnceValue(governed))
}

// GovernedCaller reports whether ctx's helper requests are a governed program's. It fails closed: a request whose
// context carries no WithGovernedCaller marker is classified by this process's own run membership (processGoverned),
// so every entry point that starts helpers is covered without marking each one, and a governed program cannot make
// its requests look ungoverned by going through a command that sets no marker. A process inside a run, or that
// cannot tell, is governed; a marker can only add what the process's own membership does not already say.
func GovernedCaller(ctx context.Context) bool {
	if processGoverned() {
		return true
	}
	governed, ok := ctx.Value(governedCallerKey{}).(func() bool)
	return ok && governed()
}

// selfAnswer is peer.Self, a variable so a test can say where this process stands.
var selfAnswer = peer.Self

// processGoverned is this process's own run membership, read once when a request first needs a helper slot:
// inside a run, looking like it, or unreadable is governed (the answer is read through Outside alone); only a process shown to
// be outside every run may take the personHelperReserve slots.
var processGoverned = membership()

// membership is a fresh once-only reading of selfAnswer (processGoverned's).
func membership() func() bool {
	return sync.OnceValue(func() bool {
		return !selfAnswer().Outside()
	})
}

// helperSlots is the order in which a request tries the kernel reservation names: a governed request only the
// shared ones; any other the reserved ones first, then the shared, so it leaves the shared to governed requests
// while it can. The reserve scales with the bound (a test's smaller pool reserves cap/8).
func helperSlots(governed bool) []int {
	limit := cap(processWorkers)
	shared := limit - helperReserve(limit)
	var slots []int
	if !governed {
		for slot := shared; slot < limit; slot++ {
			slots = append(slots, slot)
		}
	}
	for slot := range shared {
		slots = append(slots, slot)
	}
	return slots
}

// Synthetic-capacity lifecycle tests use a separate kernel reservation pool.
// Production commands always share this default within the uid and network namespace.
var helperReservationPool = "tego.contracts-check"

type helperCredentials struct {
	Creds sys.TaskCreds
	Full  helperAuthority
	Error string
	// Pid is the worker's own process id, so a caller that abandons it can tell whether it still holds its slot.
	// It is no part of the authority compared by equal.
	Pid int
}

// helperAuthority records the authority TaskCreds does not describe. In
// particular, an exec can replenish permitted capabilities while leaving the
// effective set empty. A helper must not acquire that latent authority either.
type helperAuthority struct {
	UIDs, GIDs [4]uint32
	// Caps is inheritable, permitted, effective, bounding and ambient, in order.
	Caps                [5]uint64
	NoNewPrivs, Seccomp uint64
	Securebits          int
}

func (a helperCredentials) equal(b helperCredentials) bool {
	return a.Creds.Equal(b.Creds) && a.Full.UIDs == b.Full.UIDs && a.Full.GIDs == b.Full.GIDs &&
		a.Full.Caps == b.Full.Caps &&
		a.Full.NoNewPrivs == b.Full.NoNewPrivs && a.Full.Seccomp == b.Full.Seccomp &&
		a.Full.Securebits == b.Full.Securebits
}

func readHelperCredentials() (helperCredentials, error) {
	data, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return helperCredentials{}, fmt.Errorf("%w: helper status: %w", sys.ErrCredentials, err)
	}
	creds, err := parseHelperCredentials(data)
	if err != nil {
		return helperCredentials{}, err
	}
	creds.Pid = os.Getpid()
	creds.Full.Securebits, err = unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		return helperCredentials{}, fmt.Errorf("%w: helper securebits: %w", sys.ErrCredentials, err)
	}
	return creds, nil
}

func parseHelperCredentials(data []byte) (helperCredentials, error) {
	var out helperCredentials
	var err error
	out.Creds, err = sys.ParseStatusCreds(data)
	if err != nil {
		return out, err
	}
	seen := make(map[string]bool)
	caps := []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
	for _, line := range strings.Split(string(data), "\n") {
		key, raw, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		capIndex := slices.Index(caps, key)
		if key != "Uid" && key != "Gid" && key != "Groups" && capIndex < 0 && key != "NoNewPrivs" && key != "Seccomp" {
			continue
		}
		if seen[key] {
			return out, fmt.Errorf("%w: duplicate helper status field %s", sys.ErrCredentials, key)
		}
		seen[key] = true
		fields := strings.Fields(raw)
		parse := func(value string, base, bits int) (uint64, error) {
			n, err := strconv.ParseUint(value, base, bits)
			if err != nil {
				return 0, fmt.Errorf("%w: helper status field %s: %w", sys.ErrCredentials, key, err)
			}
			return n, nil
		}
		switch key {
		case "Uid", "Gid":
			if len(fields) != 4 {
				return out, fmt.Errorf("%w: helper status field %s needs four ids", sys.ErrCredentials, key)
			}
			ids := &out.Full.UIDs
			if key == "Gid" {
				ids = &out.Full.GIDs
			}
			for i, field := range fields {
				n, err := parse(field, 10, 32)
				if err != nil {
					return out, err
				}
				ids[i] = uint32(n)
			}
		case "Groups":
			// ParseStatusCreds already validated and sorted this list.

		default:
			if len(fields) != 1 {
				return out, fmt.Errorf("%w: helper status field %s needs one value", sys.ErrCredentials, key)
			}
			base := 10
			if capIndex >= 0 {
				base = 16
			}
			n, err := parse(fields[0], base, 64)
			if err != nil {
				return out, err
			}
			switch {
			case capIndex >= 0:
				out.Full.Caps[capIndex] = n
			case key == "NoNewPrivs":
				out.Full.NoNewPrivs = n
			case key == "Seccomp":
				out.Full.Seccomp = n
			}
		}
	}
	if len(seen) != 10 {
		return out, fmt.Errorf("%w: helper status lacks a required authority field", sys.ErrCredentials)
	}
	return out, nil
}

type exchangeResult struct {
	body     []byte
	err      error
	reusable bool
}

// frameReady is the status byte of the one-byte frame a worker writes after it has decoded a request and before it
// runs the operation: the helper is alive and its next step is the location. Reply frames carry status 0 or 1.
const frameReady = 2

// framePause and frameResume stop and start the location clock (PauseLocation): the helper is about to do work that
// does not touch the location, such as a draft compile, and says for how long at most (eight bytes, big endian,
// nanoseconds, after the status byte); later it says the work has ended. Both are written between the ready frame
// and the reply.
const (
	framePause  = 3
	frameResume = 4
)

// frameEvent is a control frame as the caller sees it.
type frameEvent struct {
	kind byte
	max  time.Duration
}

// makeUndumpable is the one place this package sets PR_SET_DUMPABLE 0 on its own process, with a read-back
// (sys.MakeUndumpable). A variable so a test can fail it.
var makeUndumpable = sys.MakeUndumpable

// HelperMain runs one private launcher or worker. A launcher never examines a
// recorded path and exits without waiting for its worker. The caller reaps the
// launcher before sending any request, so a blocked worker cannot hold up the
// caller's process exit (ADR 0144).
func HelperMain(args []string) int {
	if len(args) != 1 {
		return identity.ExitError
	}
	// A helper re-executes the program image, so it is dumpable again whatever its caller was. It is handed the contract
	// text, the machine's snapshot and the recorded path, and answers what a check shows, so it is made undumpable before
	// it reads any of them, as the caller that holds secrets is, and does not run when that cannot be done.
	if err := makeUndumpable(); err != nil {
		return identity.ExitError
	}
	switch args[0] {
	case "launcher", "idle-launcher":
		return launchWorker(args[0] == "idle-launcher")
	case "worker", "idle-worker":
		return serveRequest(args[0] == "idle-worker")
	default:
		return identity.ExitError
	}
}

// launchWorker starts the worker. An idle launcher (a governed request's) first lowers its own thread to the lowest
// CPU priority the system allows (proc.LowerPriority) and starts the worker from it, so the worker, and what it
// starts (the dashboard's compiler children), run at that priority from their first instruction: a governed
// program's checks can keep a slot, but never win the CPU from a person's own check, which starts a normal launcher.
// Nothing is raised: only the launcher's own thread and what it forks are lowered. The thread is not given back:
// the launcher exits after the start.
func launchWorker(idle bool) int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if idle {
		if _, err := proc.LowerPriority(); err != nil {
			return identity.ExitError
		}
	}
	mode := "worker"
	if idle {
		mode = "idle-worker"
	}
	cmd := helperProcess(mode, os.Stdin, os.Stdout, os.Stderr)
	if _, err := proc.Start(cmd); err != nil {
		return identity.ExitError
	}
	// The worker is reaped by its new parent after this launcher exits. Waiting
	// here would recreate the dead-mount exit dependency we are removing.
	if err := cmd.Process.Release(); err != nil {
		return identity.ExitError
	}
	return identity.ExitOK
}

func helperProcess(mode string, input, output, lease *os.File) *proc.Cmd {
	cmd := proc.Command("/proc/self/exe", HelperCommand, mode)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, lease
	return cmd
}

// Abstract UNIX names live in the network namespace and vanish only after the
// last socket fd closes. A worker retains its reservation on fd 2, so a fresh
// CLI process cannot exceed the shared bound by abandoning another batch.
// No messages are sent or read; a hostile bind can only refuse a check.
func reserveHelper(ctx context.Context, euid uint32, governed bool) (*net.UnixConn, *os.File, error) {
	return reserveHelperWith(ctx, euid, governed, net.ListenUnixgram)
}

func reserveHelperWith(ctx context.Context, euid uint32, governed bool, listen func(string, *net.UnixAddr) (*net.UnixConn, error)) (*net.UnixConn, *os.File, error) {
	// Closing a caller's pipes does not release the worker's kernel lease until
	// it exits. Wait for that healthy retirement within the start-up budget;
	// a blocked worker still retains its slot and cannot grow the pool.
	//
	// What the wait knows about a slot that is taken: whether the helper that holds it is one this process abandoned
	// after the helper had said it was ready and used up its location budget, and is still alive (stuckAt: a check
	// stuck on a location). Every other slot is held by a helper nothing is known about: another command's, or a
	// healthy worker not yet gone. When every slot is held by a stuck check of this process nothing can free one by
	// waiting, and the refusal comes at once, in the disk's words when every one of them is stuck on this computer's own disk, in the mount's when any is stuck on a mount. Otherwise the wait goes on until the start-up
	// budget ends, and says only how many helpers are alive.
	//
	// The first time every slot is found taken, the holders nothing is known about are looked at once (fix29): when each
	// is identified and older than any helper can live (helperMaxLifetime) it is stuck by definition, and the refusal
	// comes at once as for this process's own stuck checks. A holder that is younger, or that cannot be identified or
	// read, keeps the wait.
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	judged := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, &slotsTaken{alive: cap(processWorkers), err: err}
		}
		slots := helperSlots(governed)
		taken, stuckN, diskN := 0, 0, 0
		var unknown []string // the taken slots whose holder this process knows nothing about
		for _, slot := range slots {
			name := fmt.Sprintf("@%s.%d.%d", helperReservationPool, euid, slot)
			reservation, err := listen("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
			if errors.Is(err, unix.EADDRINUSE) {
				taken++
				if stuckAt(name) {
					stuckN++
					if stuckOnDisk(name) {
						diskN++
					}
				} else {
					unknown = append(unknown, name)
				}
				continue
			}
			if err != nil {
				return nil, nil, fmt.Errorf("reserve filesystem helper: %w", err)
			}
			lease, err := reservation.File()
			if err != nil {
				closeReservation(reservation)
				return nil, nil, fmt.Errorf("duplicate filesystem helper reservation: %w", err)
			}
			forgetStuck(name)
			return reservation, lease, nil
		}
		if taken > 0 && taken == len(slots) && stuckN == taken {
			if diskN == stuckN {
				// Every slot is held by a helper stuck on this computer's own disk: the disk's words, as for the checks
				// themselves. One holder stuck on a mount is enough for the mount's (below): the stricter reading wins.
				return nil, nil, &unavailableError{err: &stuckHelpers{err: fmt.Errorf("%d earlier checks are still waiting for this computer's disk, and each holds a filesystem helper slot, so no helper can start: %w", stuckN, context.DeadlineExceeded)}, fault: faultDisk}
			}
			return nil, nil, CheckUnavailable(&stuckHelpers{err: fmt.Errorf("%d earlier checks are still stuck on a location, and each holds a filesystem helper slot, so no helper can start: %w", stuckN, context.DeadlineExceeded)})
		}
		if taken > 0 && taken == len(slots) && !judged {
			judged = true
			if holdersStuckForGood(unknown, localCheck(ctx)) {
				return nil, nil, CheckUnavailable(&stuckHelpers{err: fmt.Errorf("%d earlier checks are still stuck on a location that does not answer, and each holds a filesystem helper slot, so no helper can start: %w", taken, context.DeadlineExceeded)})
			}
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
	}
}

func closeReservation(reservation *net.UnixConn) {
	// It carries no data. The duplicated lease owns the reservation after spawn.
	_ = reservation.Close()
}

// serveRequest answers requests until the request pipe closes. A governed request's worker (idle, started by an idle
// launcher) is a governed program's process for as long as it lives: whatever it starts or asks of the
// dashboard's own services (the compiler children's slots, draftcompile) takes only the shares kept for governed
// callers, as the helper slot it holds does.
func serveRequest(governed bool) int {
	if governed {
		processGoverned = func() bool { return true }
	}
	// Before the first frame: a caller that has read it knows the lock is taken (holdReservation).
	holdReservation()
	workerContext, cancelWorker := helperRequestContext(os.Stdin)
	defer cancelWorker()
	// Every request starts with the worker's actual authority, on the same
	// locked thread that will perform the filesystem operations. Reuse must not
	// bypass the post-exec comparison or carry changed authority to a later call.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		header, err := readHelperCredentials()
		if err != nil {
			header.Error = err.Error()
		}
		encoded, err := json.Marshal(header)
		if err != nil || writeFrame(os.Stdout, encoded) != nil || header.Error != "" {
			return identity.ExitError
		}
		request, err := readFrame(os.Stdin, maxExchangeBytes)
		if errors.Is(err, io.EOF) {
			return identity.ExitOK
		}
		if err != nil {
			return identity.ExitError
		}
		// Operations may set PATH or other process state. Every reused request
		// starts with the same empty environment as the original exec.
		os.Clearenv()
		ready := func() error { return writeFrame(os.Stdout, []byte{frameReady}) }
		pauser := &helperPauser{
			pause: func(max time.Duration) error {
				frame := make([]byte, 9)
				frame[0] = framePause
				binary.BigEndian.PutUint64(frame[1:], uint64(max))
				return writeFrame(os.Stdout, frame)
			},
			resume: func() error { return writeFrame(os.Stdout, []byte{frameResume}) },
		}
		requestContext := context.WithValue(context.WithValue(workerContext, helperReadyKey{}, ready), helperPauseKey{}, pauser)
		body, err := handleRequestContext(requestContext, request)
		status := byte(0)
		if err != nil {
			status, body = 1, []byte(err.Error())
		}
		if len(body) > maxExchangeBytes-1 {
			status, body = 1, []byte("filesystem helper reply exceeds byte bound")
		}
		if err := writeFrame(os.Stdout, append([]byte{status}, body...)); err != nil {
			return identity.ExitError
		}
	}
}

// The request pipe is also the worker's lifetime signal. Watching only HUP/ERR
// preserves framing: no watcher reads or consumes request bytes. One watcher per
// worker cancels a recovered operation before it can submit a deferred change.
func helperRequestContext(input *os.File) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	lifetime := &helperLifetime{Context: ctx, cancel: cancel, input: input}
	ctx = context.WithValue(lifetime, helperLifetimeKey{}, lifetime)
	go func() {
		defer cancel()
		for lifetime.Context.Err() == nil {
			if lifetime.disconnected(100) {
				return
			}
		}
	}()
	return ctx, cancel
}

type helperLifetimeKey struct{}

// helperReadyKey carries the worker's ready signal to handleRequestContext (absent in a direct call).
type helperReadyKey struct{}

type helperLifetime struct {
	context.Context
	cancel context.CancelFunc
	input  *os.File
}

func (l *helperLifetime) disconnected(timeout int) bool {
	for {
		disconnected := false
		err := sys.FileDo(l.input, func(fd int) error {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLHUP | unix.POLLERR}}
			_, err := unix.Poll(fds, timeout)
			disconnected = fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0
			return err
		})
		if errors.Is(err, unix.EINTR) {
			if l.Context.Err() != nil {
				return true
			}
			continue
		}
		return err != nil || disconnected
	}
}

func (l *helperLifetime) Err() error {
	// A resumed read can reach a pre-write check before the watcher is scheduled.
	// Check the pipe here too, without consuming any framed request bytes.
	if l.Context.Err() == nil && l.disconnected(0) {
		l.cancel()
	}
	return l.Context.Err()
}

type helperSessionKey struct{}

type helperSession struct {
	gate   chan struct{}
	worker *helperWorker
	closed bool
}

type helperWorker struct {
	cmd           *proc.Cmd
	send, receive *os.File
	started       bool
	// release gives its slots back to the pools it took them from (admitWorker); nil for a worker that holds none.
	release func()
	once    sync.Once
	// slot is the name of the kernel reservation the worker holds, pid and start its own process (from its first
	// frame and /proc): what is needed to tell later that an abandoned worker still holds its slot (markStuck).
	slot  string
	pid   int
	start uint64
}

// WithHelperSession reuses one bounded helper for sequential checks in a command
// or page request. Close it when that request ends. Nested callers share the
// existing session. After an abandoned check, a later check starts a new helper.
// Close permanently ends the session, including for detached child contexts.
func WithHelperSession(ctx context.Context) (context.Context, func()) {
	if _, ok := ctx.Value(helperSessionKey{}).(*helperSession); ok {
		return ctx, func() {}
	}
	ctx = WithCallerContext(ctx)
	ctx, cancel := context.WithCancel(ctx)
	session := &helperSession{gate: make(chan struct{}, 1)}
	session.gate <- struct{}{}
	ctx = context.WithValue(ctx, helperSessionKey{}, session)
	return ctx, func() {
		cancel()
		// Cancellation makes an active exchange close its pipes and release this
		// gate; a deliberately detached context instead keeps its check deadline.
		// Wait for that owner, never for worker exit or mount recovery. A nonblocking
		// attempt could miss its final release and leave an idle worker alive.
		<-session.gate
		session.closed = true
		if session.worker != nil {
			session.worker.close()
			session.worker = nil
		}
		session.gate <- struct{}{}
	}
}

func (w *helperWorker) close() {
	w.once.Do(func() {
		closePipe(w.send)
		closePipe(w.receive)
		if w.release != nil {
			w.release()
		}
	})
}

// UnavailableLocation is the explanation for a check whose location did not answer within CheckTimeout, counted from
// the moment the helper reported it was about to touch it.
const UnavailableLocation = "cannot tell: this location does not answer (a disconnected or stuck mount?)"

// StartupUnavailable is the explanation for a check whose helper did not start, or did not report ready, within
// StartTimeout: the location was never asked.
const StartupUnavailable = "cannot tell: Tego's checker did not start in time (the machine is very busy); try again"

// CheckTooSlow is the explanation for a check whose location budget ran out while the kernel's counters said its
// helper was starved of a CPU for the whole of the cap: the helper did not finish, and the location is not known to
// be at fault. A write already submitted can still have reached the file, so the words do not say it did not.
const CheckTooSlow = "cannot tell: Tego's checker was too slow to finish (the machine is very busy); try again"

// CheckDisk is the explanation for a check whose location budget ran out, to the cap, while its helper sat in
// uninterruptible sleep in a function of this computer's own disk or journal (wchan.go): the location is not known to be at fault, and a
// disk that is very busy or nearly full is. It does not say a write did not happen: one already submitted may have.
const CheckDisk = "cannot tell: this computer's disk did not finish writing in time (the disk is very busy or nearly full); try again"

// CheckUnclear is the explanation for a check whose location budget ran out when the kernel's counters could not
// say why (a kernel without schedstat, or a helper that had already gone): it claims neither cause.
const CheckUnclear = "cannot tell: the check did not finish in time (a stuck location, or a very busy machine)"

// CheckWorking is the explanation for a check whose location budget ran out, to the cap, while the kernel's counters
// said its helper was on a CPU for most of the time: it was working, not stuck on a location and not kept off a CPU.
const CheckWorking = "cannot tell: the check was still working when its time ran out; try again"

// checkFault says which words a refusal after the ready frame has: the location's (blocked, the default), the busy
// machine's (starved) or neither (the counters cannot be read).
type checkFault int

const (
	faultLocation checkFault = iota
	faultStarved
	faultUnread
	faultWorking
	faultDisk
)

type unavailableError struct {
	err   error
	fault checkFault
}

func (e *unavailableError) Error() string {
	switch e.fault {
	case faultStarved:
		return CheckTooSlow + ": " + e.err.Error()
	case faultUnread:
		return CheckUnclear + ": " + e.err.Error()
	case faultWorking:
		return CheckWorking + ": " + e.err.Error()
	case faultDisk:
		return CheckDisk + ": " + e.err.Error()
	case faultLocation:
	}
	return UnavailableLocation + ": " + e.err.Error()
}
func (e *unavailableError) Unwrap() error { return e.err }

// IsCheckTooSlow reports whether err says the helper ran out of time because the machine was too busy to run it
// (CheckTooSlow), not that a location did not answer.
func IsCheckTooSlow(err error) bool {
	var u *unavailableError
	return errors.As(err, &u) && u.fault == faultStarved
}

// IsCheckWorking reports whether err says the helper ran out of time while it was working (CheckWorking).
func IsCheckWorking(err error) bool {
	var u *unavailableError
	return errors.As(err, &u) && u.fault == faultWorking
}

// IsCheckDisk reports whether err says the helper ran out of time waiting for this computer's disk (CheckDisk).
func IsCheckDisk(err error) bool {
	var u *unavailableError
	return errors.As(err, &u) && u.fault == faultDisk
}

// IsCheckUnclear reports whether err says the helper ran out of time and Tego could not tell why (CheckUnclear).
func IsCheckUnclear(err error) bool {
	var u *unavailableError
	return errors.As(err, &u) && u.fault == faultUnread
}

// startupError is a refusal before the location was asked. Its words say which: the checker did not start in time
// (StartupUnavailable), or it could not start at all (StartFailure, with the reason). Both are start-up refusals for
// every caller, refused the same way, and both still wrap their cause.
type startupError struct {
	err    error
	failed bool
}

func (e *startupError) Error() string {
	if e.failed {
		return StartFailure + ": " + e.err.Error()
	}
	return StartupUnavailable + ": " + e.err.Error()
}
func (e *startupError) Unwrap() error { return e.err }

// IsStartupUnavailable reports whether err is a refusal before the location was asked: the checker did not start in
// time, or it could not start (StartupUnavailable, StartFailure).
func IsStartupUnavailable(err error) bool {
	var startup *startupError
	return errors.As(err, &startup)
}

// IsStartFailure reports whether err says the checker could not start (StartFailure), not that it was slow.
func IsStartFailure(err error) bool {
	var startup *startupError
	return errors.As(err, &startup) && startup.failed
}

// IsLocationUnavailable reports whether err says a location did not answer (UnavailableLocation): the helper was
// blocked when its budget ran out, or failed after it had reported ready.
func IsLocationUnavailable(err error) bool {
	var unavailable *unavailableError
	return errors.As(err, &unavailable) && unavailable.fault == faultLocation
}

// saysWhatHappened is whether err already has words of its own for a check that did not finish, which no caller
// re-words: a location that did not answer, a checker that did not start or was too slow, a check that could not
// tell why, a caller that gave up, a compile that did not finish.
func saysWhatHappened(err error) bool {
	var unavailable *unavailableError
	return errors.As(err, &unavailable) || IsStartupUnavailable(err) || IsCancelledCheck(err) || IsCompileUnfinished(err)
}

// CheckUnavailable adds the common unavailable explanation while preserving the
// underlying refusal for errors.Is. Calling it twice does not repeat the words,
// and an error that already says what happened (the helper did not start, a caller gave up, a compile did not
// finish) keeps those words: the location was never asked, or nothing is known about it. A caller's own
// cancellation is not a location that does not answer.
func CheckUnavailable(err error) error {
	if err == nil {
		return nil
	}
	if saysWhatHappened(err) {
		return err
	}
	if isCancellation(err) {
		return &cancelledError{err: err}
	}
	return &unavailableError{err: err}
}

// refusal says what happened in a failed exchange. asked is whether the helper had reported it was about to touch
// the location. Before that nothing was asked of it: a deadline is the checker not starting in time, and any other
// failure (a failed fork, a refused credential check, a launcher that did not run) is the checker that could not
// start. After it every failure is the location's, except a caller that gave up.
func refusal(err error, asked bool) error {
	switch {
	case err == nil, saysWhatHappened(err):
		return err
	case isCancellation(err):
		return &cancelledError{err: err}
	case asked:
		return CheckUnavailable(err)
	case errors.Is(err, context.DeadlineExceeded) && !errors.As(err, new(*slotsTaken)):
		return &startupError{err: err}
	default:
		return &startupError{err: err, failed: true}
	}
}

// exchange sends one request to the session's helper under two budgets. The start-up budget (StartTimeout) covers the
// wait for the session's gate and a free helper slot, the helper's start and its ready frame; a miss is a
// startupError. The location budget (CheckTimeout, or what is left of the scope's, see WithBudget) starts when the
// helper reports it is about to touch the location, and stops while the helper pauses it (PauseLocation); a miss, or
// any other failure after that, is an unavailableError.
func exchange(ctx context.Context, request []byte) (body []byte, err error) {
	budget := budgetOf(ctx)
	if budget == nil {
		budget = newBudget()
	}
	startLeft, locationLeft := budget.left()
	asked := false // the helper has said it is about to touch the location
	if err := refuseExpired(ctx); err != nil {
		return nil, err
	}
	if len(request) > maxExchangeBytes {
		return nil, errors.New("filesystem helper request exceeds byte bound")
	}
	defer func() {
		err = refusal(err, asked)
		if !asked && IsStartupUnavailable(err) {
			budget.refuseStart(err)
		}
	}()
	// A request scope's bound (WithRequestScope) caps the start-up wait as well.
	boundLeft, bounded := budget.untilLeft()
	if bounded {
		startLeft = min(startLeft, boundLeft)
	}
	if startLeft <= 0 {
		if bounded && boundLeft <= 0 {
			if err := budget.refusal(); err != nil {
				asked = true
				return nil, err
			}
			if err := budget.startRefusal(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("the time of this request is spent: %w", context.DeadlineExceeded)
		}
		if err := budget.startRefusal(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("the start-up budget of this request is spent: %w", context.DeadlineExceeded)
	}
	if locationLeft <= 0 {
		asked = true
		if err := budget.refusal(); err != nil {
			return nil, err
		}
		return nil, &unavailableError{err: fmt.Errorf("the location budget of this request is spent: %w", context.DeadlineExceeded), fault: faultUnread}
	}
	session, ok := ctx.Value(helperSessionKey{}).(*helperSession)
	if !ok {
		var closeSession func()
		ctx, closeSession = WithHelperSession(ctx)
		defer closeSession()
		session = ctx.Value(helperSessionKey{}).(*helperSession)
	}
	startCtx, cancelStart := context.WithTimeout(ctx, startLeft)
	defer cancelStart()
	started := time.Now()
	// A free gate is taken even when the budget has just ended: the refusal then comes from the slot wait, which
	// says how many helpers are alive, and does not depend on which of two ready channels a select picks.
	select {
	case <-session.gate:
	default:
		select {
		case <-startCtx.Done():
			budget.chargeStart(time.Since(started))
			return nil, startCtx.Err()
		case <-session.gate:
		}
	}
	defer func() { session.gate <- struct{}{} }()
	if session.closed {
		return nil, context.Canceled
	}
	// Capture the current caller on every exchange. A session cannot keep using
	// an earlier caller's authority if the service changes its thread credentials.
	runtime.LockOSThread()
	as, err := readHelperCredentials()
	if err == nil && session.worker == nil {
		session.worker, err = startHelper(startCtx, as)
	}
	runtime.UnlockOSThread()
	if err != nil {
		budget.chargeStart(time.Since(started))
		return nil, err
	}
	worker := session.worker
	done := make(chan exchangeResult, 1)
	events := make(chan frameEvent)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		done <- worker.transact(ctx, as, request, func(e frameEvent) {
			select {
			case events <- e:
			case <-stop:
			}
		})
	}()
	abandon := func(err error) ([]byte, error) {
		// Closing both ends interrupts pipe I/O in the exchange goroutine. The
		// worker alone retains its kernel lease until the actual mount recovers.
		// No service goroutine waits for that recovery or for an abandoned reply.
		worker.close()
		session.worker = nil
		return nil, err
	}
	finish := func(result exchangeResult, bound error) ([]byte, error) {
		if bound != nil {
			return abandon(bound)
		}
		if result.err != nil && !result.reusable {
			worker.close()
			session.worker = nil
		}
		return result.body, result.err
	}
	// Until the ready frame: the start-up budget.
	for ready := false; !ready; {
		select {
		case result := <-done:
			// Answered, or failed, before a ready frame: nothing has asked the location.
			budget.chargeStart(time.Since(started))
			return finish(result, startCtx.Err())
		case e := <-events:
			if e.kind != frameReady {
				budget.chargeStart(time.Since(started))
				return abandon(errors.New("filesystem helper sent a control frame before it was ready"))
			}
			ready = true
		case <-startCtx.Done():
			budget.chargeStart(time.Since(started))
			return abandon(startCtx.Err())
		}
	}
	budget.chargeStart(time.Since(started))
	asked = true
	budget.markAsked()
	// From the ready frame: the location budget, which runs while the helper touches the location and stops while it
	// says it does something else (a pause frame), for no longer than it says it needs. When it runs out, the kernel's
	// counters for the helper say whether it was blocked, starved of a CPU, or unreadable (Watch): a starved helper
	// is given another step, up to the scope's cap, and only a blocked one is a location that did not answer.
	watch := NewWatchWith(readScheduler, worker.pid, worker.start, time.Now)
	var (
		clock   = time.NewTimer(locationLeft)
		pauseAt = time.NewTimer(time.Hour)
		running = time.Now() // when the clock last started
		left    = locationLeft
		granted time.Duration
		paused  = false
	)
	pauseAt.Stop()
	// bound ends the exchange when the request scope's bound does (WithRequestScope), whatever the budgets would
	// still allow: a nil channel when the scope has none.
	var boundC <-chan time.Time
	if left, ok := budget.untilLeft(); ok {
		boundTimer := time.NewTimer(max(left, 0))
		defer boundTimer.Stop()
		boundC = boundTimer.C
	}
	defer clock.Stop()
	defer pauseAt.Stop()
	defer func() {
		if !paused {
			left -= time.Since(running)
		}
		budget.chargeLocation(locationLeft + granted - left)
	}()
	// expire decides what the end of the location budget means. It returns nil when the helper was starved, was
	// working on a CPU or was waiting for this computer's disk, and the scope may give it another step (the clock then runs on), and otherwise the refusal,
	// in the words of what the counters said. A helper that was blocked is stuck on its slot (stuck says so); one
	// that could not be read, or that was starved or working to the cap, is not known to be.
	local := localCheck(ctx)
	expire := func(stuck bool) error {
		verdict := watch.JudgeAt(local)
		switch verdict {
		case Starved, Running, BlockedDisk:
			// grant gives nothing past the request scope's bound, so a helper still starved, working or waiting for the
			// disk at that bound is refused as one at the cap. A wait for this computer's own disk is slow, not stuck:
			// the disk will answer, so it is given the steps a starved helper is; a wait in a mount is not.
			if step := budget.grant(local && verdict == BlockedDisk); step > 0 {
				if local && verdict == BlockedDisk {
					noteDiskWait(ctx, budget)
				}
				granted += step
				left += step
				clock.Reset(max(left-time.Since(running), 0))
				return nil
			}
			switch verdict {
			case Running:
				return budget.refuse(&unavailableError{err: context.DeadlineExceeded, fault: faultWorking})
			case BlockedDisk:
				// The helper holds its slot until the disk answers.
				if stuck {
					markStuck(worker, local)
				}
				return budget.refuse(&unavailableError{err: context.DeadlineExceeded, fault: faultDisk})
			}
			return budget.refuse(&unavailableError{err: context.DeadlineExceeded, fault: faultStarved})
		case Unreadable:
			return budget.refuse(&unavailableError{err: context.DeadlineExceeded, fault: faultUnread})
		}
		if stuck {
			markStuck(worker, false)
		}
		return budget.refuse(&unavailableError{err: context.DeadlineExceeded})
	}
	// bound is why a reply that has arrived cannot be trusted: the caller's own deadline or cancellation, or a
	// location budget that ran out before the reply was read (the deadline also wins a race with a reply, unless the
	// helper was starved and is given more time).
	bound := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !paused && time.Since(running) >= left {
			return expire(false)
		}
		return nil
	}
	for {
		select {
		case result := <-done:
			return finish(result, bound())
		case e := <-events:
			switch {
			case e.kind == framePause && !paused:
				left -= time.Since(running)
				paused = true
				watch.Pause()
				if !clock.Stop() {
					select {
					case <-clock.C:
					default:
					}
				}
				pauseAt.Reset(max(min(e.max, PauseLimit), 0))
			case e.kind == frameResume && paused:
				paused = false
				watch.Resume()
				running = time.Now()
				clock.Reset(max(left, 0))
				if !pauseAt.Stop() {
					select {
					case <-pauseAt.C:
					default:
					}
				}
			default:
				return abandon(errors.New("filesystem helper sent an unexpected control frame"))
			}
		case <-clock.C:
			// The location budget ran out: starved, the helper is given more; otherwise it stays, on its slot.
			if err := expire(true); err != nil {
				return abandon(err)
			}
		case <-boundC:
			// The request's own time is spent (WithRequestScope). A helper that is paused is a compile that did not
			// finish; any other is judged by its counters, with nothing more to give it.
			if paused {
				return abandon(CompileNotFinished(context.DeadlineExceeded))
			}
			if err := expire(true); err != nil {
				return abandon(err)
			}
			return abandon(budget.refuse(&unavailableError{err: context.DeadlineExceeded, fault: faultStarved}))
		case <-pauseAt.C:
			// The helper said its other work would take at most so long, and it has not ended. Nobody asked the
			// location while it was paused, so this is not the mount's words.
			return abandon(CompileNotFinished(context.DeadlineExceeded))
		case <-ctx.Done():
			return abandon(ctx.Err())
		}
	}
}

// admitWorker takes this process's worker slot within ctx: a governed request's from the governedWorkers share
// as well, so the personHelperReserve slots stay for other requests. release gives back what it took.
func admitWorker(ctx context.Context, governed bool) (release func(), err error) {
	// The pools as they are now: a release gives back to the pools it took from, even if the variables change later.
	workers, governedPool := processWorkers, governedWorkers
	busy := func() error {
		return fmt.Errorf("%d filesystem helpers are still alive: %w", cap(workers), ctx.Err())
	}
	if governed {
		select {
		case governedPool <- struct{}{}:
		case <-ctx.Done():
			return nil, busy()
		}
	}
	select {
	case workers <- struct{}{}:
	case <-ctx.Done():
		if governed {
			<-governedPool
		}
		return nil, busy()
	}
	return func() {
		<-workers
		if governed {
			<-governedPool
		}
	}, nil
}

// The caller holds its OS thread from credential capture through proc.Start.
func startHelper(ctx context.Context, as helperCredentials) (*helperWorker, error) {
	// Asked before the admission wait starts, so the caller's lookup does not shorten it. The wait for a slot is
	// part of ctx, the exchange's start-up budget.
	governed := GovernedCaller(ctx)
	release, err := admitWorker(ctx, governed)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*helperWorker, error) { release(); return nil, err }
	input, send, err := os.Pipe()
	if err != nil {
		return fail(fmt.Errorf("filesystem helper request pipe: %w", err))
	}
	receive, output, err := os.Pipe()
	if err != nil {
		closePipe(input)
		closePipe(send)
		return fail(fmt.Errorf("filesystem helper reply pipe: %w", err))
	}
	reservation, lease, err := reserveHelper(ctx, as.Creds.EUID, governed)
	var cmd *proc.Cmd
	slot := ""
	if reservation != nil {
		slot = reservation.LocalAddr().String()
	}
	if err == nil {
		mode := "launcher"
		if governed {
			mode = "idle-launcher"
		}
		cmd = helperProcess(mode, input, output, lease)
		_, err = proc.Start(cmd)
	}
	if lease != nil {
		closePipe(lease)
	}
	if reservation != nil {
		closeReservation(reservation)
	}
	closePipe(input)
	closePipe(output)
	if err != nil {
		closePipe(send)
		closePipe(receive)
		return fail(fmt.Errorf("start filesystem helper: %w", err))
	}
	return &helperWorker{cmd: cmd, send: send, receive: receive, slot: slot, release: release}, nil
}

// transact runs one request on the worker. events, when not nil, is called for each control frame that arrives before
// the reply: ready, once, then any pairs of pause and resume.
func (w *helperWorker) transact(ctx context.Context, as helperCredentials, request []byte, events func(frameEvent)) exchangeResult {
	// Only the short launcher is waited for. It exits before any request is sent.
	if !w.started {
		if err := w.cmd.Wait(); err != nil {
			return exchangeResult{err: fmt.Errorf("filesystem helper launcher: %w", err)}
		}
		w.started = true
	}
	encoded, err := readFrame(w.receive, 1<<20)
	if err != nil {
		return exchangeResult{err: fmt.Errorf("filesystem helper credentials: %w", err)}
	}
	var header helperCredentials
	if err := json.Unmarshal(encoded, &header); err != nil {
		return exchangeResult{err: fmt.Errorf("filesystem helper credentials: %w", err)}
	}
	if header.Error != "" || !as.equal(header) {
		return exchangeResult{err: fmt.Errorf("%w: filesystem helper credentials differ after exec", sys.ErrCredentials)}
	}
	if w.pid != header.Pid || w.start == 0 {
		w.pid, w.start = header.Pid, processStart(header.Pid)
	}
	if err := ctx.Err(); err != nil {
		return exchangeResult{err: err}
	}
	if err := writeFrame(w.send, request); err != nil {
		return exchangeResult{err: fmt.Errorf("filesystem helper request: %w", err)}
	}
	var body []byte
	for {
		body, err = readFrame(w.receive, maxExchangeBytes)
		if err != nil || len(body) == 0 || body[0] < frameReady {
			break
		}
		event := frameEvent{kind: body[0]}
		switch {
		case body[0] == frameReady && len(body) == 1, body[0] == frameResume && len(body) == 1:
		case body[0] == framePause && len(body) == 9:
			event.max = time.Duration(binary.BigEndian.Uint64(body[1:]))
		default:
			return exchangeResult{err: errors.New("filesystem helper reply has invalid status")}
		}
		if events != nil {
			events(event)
		}
	}
	if err != nil {
		return exchangeResult{err: fmt.Errorf("filesystem helper reply: %w", err)}
	}
	if len(body) == 0 || body[0] > 1 {
		return exchangeResult{err: errors.New("filesystem helper reply has invalid status")}
	}
	if body[0] == 1 {
		return exchangeResult{err: fmt.Errorf("filesystem helper: %s", body[1:]), reusable: true}
	}
	return exchangeResult{body: body[1:]}
}

func writeFrame(w io.Writer, body []byte) error {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(body)))
	if n, err := w.Write(length[:]); err != nil {
		return err
	} else if n != len(length) {
		return io.ErrShortWrite
	}
	if n, err := w.Write(body); err != nil {
		return err
	} else if n != len(body) {
		return io.ErrShortWrite
	}
	return nil
}

func readFrame(r io.Reader, limit uint64) ([]byte, error) {
	var length [8]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint64(length[:])
	if size > limit {
		return nil, errors.New("filesystem helper frame exceeds byte bound")
	}
	body := make([]byte, int(size))
	_, err := io.ReadFull(r, body)
	return body, err
}

func closePipe(f *os.File) {
	// Closing an already closed pipe is expected when cancellation races its
	// owning goroutine. No data is committed by a pipe close.
	_ = f.Close()
}

// ErrHelpersStuck is the cause of a refusal whose helper slots are all held by earlier checks that are stuck on a
// location (errors.Is): nothing can free a slot by waiting, so no new helper can start.
var ErrHelpersStuck = errors.New("earlier checks are still stuck on a location")

// stuckHelpers is that refusal's error, which still says how many and why in its own words.
type stuckHelpers struct{ err error }

func (e *stuckHelpers) Error() string        { return e.err.Error() }
func (e *stuckHelpers) Unwrap() error        { return e.err }
func (e *stuckHelpers) Is(target error) bool { return target == ErrHelpersStuck }

// IsHelpersStuck reports whether err says every helper slot is held by an earlier check stuck on a location.
func IsHelpersStuck(err error) bool { return errors.Is(err, ErrHelpersStuck) }

// HelpersStuck is the explanation for that refusal, for a page that shows the cause by its type.
const HelpersStuck = "earlier checks are still stuck on a location, and each holds a helper slot, so no new check can start"
