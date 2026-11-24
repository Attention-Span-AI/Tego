// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	rtcgroup "github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/selfbin"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

const scopeVerb = "__user_scope"

var scopeTimeout = 10 * time.Second

type scopeKey struct{}
type scopeInvocation struct {
	argv []string
	once bool
	// outer is the launcher's end of the interrupt channel to the outer process (launch.Arbiter), nil when the
	// outer process offered none.
	outer launch.Conn
}

// scopePlacement asks the same read-only question as doctor's D3 and the guide. In particular, a read failure is
// never ErrBesideSubtree and cannot cause a move. There is no second test based on SSH or environment variables.
var scopePlacement = func() error {
	fs, err := rtcgroup.Detect(os.Getuid())
	if err != nil {
		return err
	}
	return fs.CanPlace()
}

// scopeRequest travels over a pipe, not systemd-run's argv: systemd >= 254 expands dollar signs in scope arguments.
// Gob preserves arbitrary argument bytes too. Environment is restored in the new launcher, including values systemd
// adds or changes (INVOCATION_ID). None of these values is authority to move or to bypass placement.
type scopeRequest struct {
	Argv, Env []string
	Rehearse  bool
}

type scopePlan struct {
	Runner, Binary string
	Request        scopeRequest
	Env            []string
}

var scopeExec = executeUserScope
var scopePaths = userScopePaths

func userScopePaths() (runner, binary string, err error) {
	runner, err = guide.SystemdRunPath()
	if err != nil {
		return "", "", err
	}
	binary, why := selfbin.Path(os.Executable)
	if why != "" {
		return "", "", errors.New(why)
	}
	return runner, binary, nil
}

// enterUserScope is called after usage checks, before a contract, ledger, run id or run cgroup can be made. A nil
// invocation is an in-process caller, not a command to re-execute. Service units keep their existing lifetime.
func enterUserScope(ctx context.Context, stderr io.Writer) (int, bool) {
	in, ok := ctx.Value(scopeKey{}).(scopeInvocation)
	if !ok || in.once {
		return 0, false
	}
	code, attempted, err := tryUserScope(ctx, in, false, stderr)
	if !attempted {
		return 0, false
	}
	if err == nil {
		return code, true
	}
	if ctx.Err() != nil {
		return 130, true
	}
	var unknown *scopeNotOutside
	if errors.As(err, &unknown) {
		// Not a failed start: no scope was tried. The words are the answer's own, under [governed] as every
		// refusal for a process that cannot be shown to be outside every run.
		message(stderr, "", 0, 0, notOutside(scopeName(in.argv), unknown.answer, "",
			"nothing was started", ""), codeGoverned)
		return identity.ExitLauncher, true
	}
	scopeFailure(stderr, in, err)
	outsideHint(stderr, "run this again there")
	return identity.ExitLauncher, true
}

// scopeNotOutside is an entry that was not tried because this process cannot be shown to be outside every run,
// while its cgroup path shows none (the rule's unknown: a cgroup namespace that is not the machine's first one and
// has no proof). A path that shows a run is not this error: such a caller is not moved and no entry is reported.
type scopeNotOutside struct{ answer runscope.Answer }

func (e *scopeNotOutside) Error() string {
	return "this process cannot be shown to be outside every tego run: " + runscope.Why(e.answer)
}

// scopeInitCgroup is a fact, never a distribution-name or environment heuristic: pid 1's cgroup file names exactly
// /init.scope (runscope.Unified, as the rule's own read of it does). Older namespace layouts that hide the system
// manager cannot establish the entry precondition.
var scopeInitCgroup = func() bool {
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	cg, err := runscope.Unified(b)
	return err == nil && cg == runscope.InitScope
}

func tryUserScope(ctx context.Context, in scopeInvocation, rehearse bool, stderr io.Writer) (int, bool, error) {
	placeErr := scopePlacement()
	if !errors.Is(placeErr, rtcgroup.ErrBesideSubtree) {
		return 0, false, nil
	}
	// The membership guard: only a process shown to be outside every run enters. One whose path shows a run stays
	// where it is and nothing is tried (a nested run keeps the enclosing run's limits). One that cannot be shown to
	// be outside (a cgroup namespace that is not the machine's first one, without the rule's proof) is not moved
	// either, and is told why.
	if a := selfAnswer(); !a.Outside() {
		if !runscope.CouldNotTell(a) {
			return 0, false, nil
		}
		return 0, true, &scopeNotOutside{answer: a}
	}
	if !scopeInitCgroup() {
		return 0, true, errors.New("the service manager is not at the top of this cgroup tree; entry was not attempted")
	}
	runner, binary, err := scopePaths()
	if err != nil {
		return 0, true, err
	}
	code, err := scopeExec(ctx, scopePlan{Runner: runner, Binary: binary,
		Request: scopeRequest{Argv: in.argv, Env: os.Environ(), Rehearse: rehearse}, Env: scopeManagerEnv(os.Environ())}, stderr)
	if err == nil && rehearse && code != 0 {
		err = fmt.Errorf("user scope rehearsal exited %d", code)
	}
	return code, true, err
}

func scopeFailure(stderr io.Writer, in scopeInvocation, err error) {
	message(stderr, "", 0, 0, "tego "+in.argv[1]+": could not open a user scope: "+err.Error(), backend.CodeTierUnavailable)
}

// rehearseUserScope leaves this command in its original cgroup. Only placement is proved; D3 still checks the
// delegated tree, controllers and atomic kill. A failed rehearsal retains the ordinary in-place report and exit.
func rehearseUserScope(ctx context.Context, stderr io.Writer) context.Context {
	in, ok := ctx.Value(scopeKey{}).(scopeInvocation)
	if !ok || in.once {
		return ctx
	}
	_, attempted, err := tryUserScope(ctx, in, true, stderr)
	if !attempted {
		return ctx
	}
	var unknown *scopeNotOutside
	if errors.As(err, &unknown) {
		// No scope was tried, and the report that follows is of this shell as it is. The words are the answer's own.
		message(stderr, "", 0, 0, notOutside(scopeName(in.argv), unknown.answer, "",
			"no user scope was tried", "what follows describes this shell as it is"), codeGoverned)
		return ctx
	}
	if err != nil {
		scopeFailure(stderr, in, err)
		// The report and the stored check say why: run, watch and test would fail to open one as this did.
		return doctor.WithUserScopeFailure(ctx, fixText(err.Error()))
	}
	return doctor.WithUserScopePlacement(ctx)
}

// scopeName is the command as a message names it: machine check and machine test are two words, every other
// command one.
func scopeName(argv []string) string {
	if len(argv) > 2 && argv[1] == "machine" {
		return argv[1] + " " + argv[2]
	}
	return argv[1]
}

// scopeCommandFor is proc.Command; tests use a process speaking the handshake without a systemd manager.
var scopeCommandFor = proc.Command

// executeUserScope is a reviewed start before all run state and before proc.Arm (ADR 0021). The two pipes carry
// the original invocation, readiness, then permission to start. A timeout kills a child that has no permission;
// closing the pipes makes even a delayed child refuse. Once permission is sent, only the real launcher owns state.
func executeUserScope(ctx context.Context, p scopePlan, stderr io.Writer) (int, error) {
	toChild, send, err := scopePipe("scope-request")
	if err != nil {
		return 0, err
	}
	defer toChild.Close() //nolint:errcheck // the handshake's pipe end: its close carries nothing and its error loses nothing
	defer send.Close()    //nolint:errcheck // same
	receive, fromChild, err := scopePipe("scope-ready")
	if err != nil {
		return 0, err
	}
	defer receive.Close()   //nolint:errcheck // the handshake's pipe end: its close carries nothing and its error loses nothing
	defer fromChild.Close() //nolint:errcheck // same
	cmd := scopeCommandFor(p.Runner, "--user", "--scope", "--collect", "--quiet", "--no-ask-password", "--", p.Binary, scopeVerb)
	cmd.Env = p.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{toChild, fromChild}
	gate, theirs := scopeSignalChannel()
	if theirs != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, theirs) // descriptor 5: the launcher's end of the interrupt channel
		defer theirs.Close()                            //nolint:errcheck // the launcher's end is closed again after the start; only an early return reaches this
		defer func() {
			if gate != nil {
				gate.Close()
			}
		}()
	}
	// No Setsid, Setpgid, pty or I/O copier: the caller's session and job are retained.
	// JobControl owns the same stop/continue terminal transfer as the direct launcher.
	// Pdeathsig belongs to the thread which starts the process; keep it alive until Wait, even under Go scheduling.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	job := tegoruntime.NewJobControl(tegoruntime.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr})
	defer job.Close()
	sigs, stop := launch.Notify()
	if gate != nil {
		sigs, stop = launch.NotifyMarked()
	}
	defer stop()
	if _, err = proc.Start(cmd); err != nil {
		return 0, err
	}
	_ = toChild.Close() // only the child now owns these ends
	_ = fromChild.Close()
	if theirs != nil {
		_ = theirs.Close()
	}
	ready := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := gob.NewEncoder(send).Encode(p.Request)
		if err == nil {
			var b [1]byte
			_, err = io.ReadFull(receive, b[:])
			if err == nil && b[0] != 1 {
				err = scopeReason(b[0])
			}
		}
		ready <- err
	}()
	timer := time.NewTimer(scopeTimeout)
	defer timer.Stop()
	select {
	case err = <-ready:
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = errors.New("user scope startup timed out")
	}
	if err == nil {
		err = ctx.Err()
	} // cancellation wins over simultaneous readiness, before permission
	if err != nil {
		_ = cmd.Process.Kill() // still uncommitted: there can be no run state
		_ = send.Close()
		_ = receive.Close() // unblock and join the handshake worker, including a partial encode
		<-done
		_ = cmd.Wait()
		return 0, err
	}
	if !p.Request.Rehearse {
		fmt.Fprintln(stderr, "tego: opened a user scope for this run")
		_, err = send.Write([]byte{1})
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 0, err
	}
	_ = send.Close()
	_ = receive.Close()
	// All three streams are files and there are no Cmd-owned pipes or copier goroutines. Wait4 is the sole
	// reaper, so it can observe stops as well as the final status. Release closes Go's process handle afterward.
	defer func() { _ = cmd.Process.Release() }()
	type childEvent struct {
		status unix.WaitStatus
		err    error
	}
	wait := make(chan childEvent)
	go func() {
		for {
			var ws unix.WaitStatus
			_, err := unix.Wait4(cmd.Process.Pid, &ws, unix.WUNTRACED, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			wait <- childEvent{ws, err}
			if err != nil || ws.Exited() || ws.Signaled() {
				return
			}
		}
	}()
	for {
		select {
		case event := <-wait:
			if event.err != nil {
				return 0, event.err
			}
			ws := event.status
			if ws.Stopped() {
				job.Follow(ctx, cmd.Process.Pid, syscall.Signal(ws.StopSignal()))
				continue
			}
			if ws.Signaled() {
				return launch.Reraise(syscall.Signal(ws.Signal())), nil
			}
			return ws.ExitStatus(), nil
		case sig := <-sigs:
			scopeHandle(cmd, gate, sig)
		case <-gateQueries(gate):
			for _, other := range gate.Answer(sigs) {
				scopeHandle(cmd, gate, other)
			}
		}
	}
}

// scopeHandle is what the outer process does with one signal. An INT or QUIT the launcher judges from the counts
// both processes keep (launch.Gate) is not forwarded: a group-directed one reached the launcher already, and
// forwarding it by kill(2) made one Ctrl-C two. Without a listening launcher the old rule applies.
func scopeHandle(cmd *proc.Cmd, gate *launch.Gate, sig os.Signal) {
	s, ok := sig.(syscall.Signal)
	if !ok || launch.IsMarker(sig) {
		return
	}
	if gate != nil && gate.Note(s) {
		return
	}
	if shouldForwardScope(s) {
		_ = cmd.Process.Signal(s) // ESRCH means Wait4 is already ready
	}
}

// gateQueries is the gate's questions, or a channel that never yields when there is no gate.
func gateQueries(g *launch.Gate) <-chan struct{} {
	if g == nil {
		return nil
	}
	return g.Queries()
}

// scopeSignalChannel makes the stream socket the two processes count interrupts over. Both ends are owned at birth
// (ADR 0023 A10); a failure leaves the channel out and the old forwarding in place, never the run unstarted.
func scopeSignalChannel() (*launch.Gate, *os.File) {
	mine, theirs, err := sys.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, nil
	}
	local, err := mine.Release("scope-signals-outer")
	if err != nil {
		_ = theirs.Close()
		return nil, nil
	}
	remote, err := theirs.Release("scope-signals-launcher")
	if err != nil {
		_ = local.Close()
		return nil, nil
	}
	return launch.NewGate(local, nil), remote
}

// scopeNotify is launch.Notify for the launcher's run: with an interrupt channel to the outer process the INT and
// QUIT arrivals go through launch.Arbiter, so one person's interrupt is one. ready is closed once the outer process
// has acknowledged the channel (nil when there is none).
func scopeNotify(ctx context.Context) (sigs <-chan os.Signal, stop func(), ready <-chan struct{}) {
	in, ok := ctx.Value(scopeKey{}).(scopeInvocation)
	if !ok || in.outer == nil {
		sigs, stop = launch.Notify()
		return sigs, stop, nil
	}
	raw, unsubscribe := launch.NotifyMarked()
	arb := launch.NewArbiter(in.outer, raw, nil)
	return arb.Signals(), func() { arb.Close(); unsubscribe() }, arb.Ready()
}

// scopeForeground is independent of stdin: printf task | tego still belongs to its controlling terminal's job.
var scopeForeground = controllingTerminalForeground

func controllingTerminalForeground() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOCTTY, 0)
	if err != nil {
		return false
	}
	defer tty.Close() //nolint:errcheck // a read-only /dev/tty opened for one ioctl
	foreground := false
	_ = sys.FileDo(tty, func(fd int) error {
		pg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		foreground = err == nil && pg == unix.Getpgrp()
		return err
	})
	return foreground
}

// For INT/QUIT, a foreground job's controlling terminal has already signalled the shared group. Only a parent
// outside that foreground group (including a process with no controlling tty) proxies them. os/signal supplies
// no siginfo, so a directed kill to a foreground parent alone must target the launcher or job group instead.
func shouldForwardScope(sig syscall.Signal) bool {
	return identity.Forwardable(sig, (sig == syscall.SIGINT || sig == syscall.SIGQUIT) && scopeForeground())
}

// scopePipe owns both fresh descriptors at birth (ADR 0023 A10), then releases them to os.File for ExtraFiles
// and the handshake's cancelable I/O. CLOEXEC prevents either parent end leaking into another concurrent exec.
// NONBLOCK makes os.NewFile register them with Go's poller, so Close can interrupt a canceled handshake.
func scopePipe(name string) (r, w *os.File, err error) {
	rd, wr, err := sys.Pipe2(unix.O_CLOEXEC | unix.O_NONBLOCK)
	if err != nil {
		return nil, nil, err
	}
	defer rd.Close() //nolint:errcheck // owns nothing once released; closes only on an early return
	defer wr.Close() //nolint:errcheck // same
	r, err = rd.Release(name + "-read")
	if err != nil {
		return nil, nil, err
	}
	w, err = wr.Release(name + "-write")
	if err != nil {
		_ = r.Close() // the first release must not leak when the second fails
		return nil, nil, err
	}
	return r, w, nil
}

// scopeManagerEnv is the environment systemd-run is started with: what it reads to reach this uid's manager and to
// print, and nothing else. It uses this uid's manager, including after sudo -u where the caller keeps another user's
// runtime directory or none (XDG_RUNTIME_DIR is always rewritten, the bus address dropped). The caller's own
// environment is not here: systemd-run is a plain exec, so it is dumpable, and it execs the re-entered launcher with
// the environment it has; the secrets of the caller's environment go to that launcher over the request FIFO, which
// the undumpable processes at both ends hold, and scopedMain rebuilds the environment from it before command dispatch.
func scopeManagerEnv(env []string) []string {
	out := make([]string, 0, 12)
	for _, e := range env {
		name, _, ok := strings.Cut(e, "=")
		if ok && scopeManagerVar(name) {
			out = append(out, e)
		}
	}
	return append(out, "XDG_RUNTIME_DIR="+filepath.Join(config.LogindRuntimeRoot, strconv.Itoa(os.Getuid())))
}

// scopeManagerVar says whether systemd-run needs the variable: the path to find tools, the account and locale
// variables, the terminal it prints to, and the knobs systemd's own tools read (SYSTEMD_LOG_*, SYSTEMD_COLORS,
// SYSTEMD_PAGER, NO_COLOR). XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS are decided by scopeManagerEnv.
func scopeManagerVar(name string) bool {
	switch name {
	case "PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TERM", "COLORTERM", "TZ", "NO_COLOR",
		"SYSTEMD_COLORS", "SYSTEMD_PAGER", "SYSTEMD_LOG_LEVEL", "SYSTEMD_LOG_COLOR", "SYSTEMD_LOG_LOCATION",
		"SYSTEMD_LOG_TIME", "SYSTEMD_LOG_TARGET":
		return true
	}
	return strings.HasPrefix(name, "LC_")
}

// scopedMain is the single re-entry. It never opens another scope. Placement and the go-ahead are checked before
// dispatch, so forging this verb or its environment cannot cause an unplaced run, nor let a governed caller escape.
func scopedMain(ctx context.Context, stdout, stderr io.Writer) int {
	request, err := sys.Inherited(3, sys.KindFIFO, "scope-request")
	if err != nil {
		return identity.ExitLauncher
	}
	defer request.Close() //nolint:errcheck // owns nothing once released below; closes only on an early return
	response, err := sys.Inherited(4, sys.KindFIFO, "scope-ready")
	if err != nil {
		return identity.ExitLauncher
	}
	defer response.Close() //nolint:errcheck // same
	// An outer process of this build offers descriptor 5; any other process or build leaves it out and the outer
	// process keeps forwarding by signal.
	var outer launch.Conn
	if signals, serr := sys.Inherited(5, sys.KindSocket, "scope-signals"); serr == nil {
		if f, rerr := signals.Release("scope-signals"); rerr == nil {
			outer = f
			defer f.Close() //nolint:errcheck // the channel's launcher end: the arbiter closes it first, a second close loses nothing
		}
	}
	rd, err := request.Release("scope-request")
	if err != nil {
		return identity.ExitLauncher
	}
	defer rd.Close() //nolint:errcheck // the handshake FIFO's read end: a close error loses nothing
	wr, err := response.Release("scope-ready")
	if err != nil {
		return identity.ExitLauncher
	}
	defer wr.Close() //nolint:errcheck // the readiness FIFO: its one write is checked where it is made
	// The request below carries the caller's whole environment, and the command it re-enters (run, watch) holds
	// secrets: this process is undumpable before the request is read (holdSecrets), or it answers 6 and starts nothing.
	if _, ok := holdSecrets(scopeVerb, io.Discard); !ok {
		_, _ = wr.Write([]byte{6})
		return identity.ExitLauncher
	}
	var in scopeRequest
	if err = gob.NewDecoder(io.LimitReader(rd, 4<<20)).Decode(&in); err != nil {
		return identity.ExitLauncher
	}
	answer := func(reason byte) int {
		_, _ = wr.Write([]byte{reason})
		return identity.ExitLauncher
	}
	if !scopeCommand(in.Argv, in.Rehearse) {
		return answer(2)
	}
	// Stage the entire environment before changing it. os.Getenv uses the first inherited entry for a duplicate;
	// preserve that value before later command startup can capture caller identity.
	env, err := scopeEnvironment(in.Env)
	if err != nil {
		return answer(5)
	}
	os.Clearenv()
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		if os.Setenv(k, v) != nil {
			return answer(5)
		}
	}
	// The re-entered process judges itself afresh: the answer is never carried in the request.
	if !selfAnswer().Outside() {
		return answer(3)
	}
	if err = scopePlacement(); err != nil {
		return answer(4)
	}
	if _, err = wr.Write([]byte{1}); err != nil {
		return identity.ExitLauncher
	}
	if in.Rehearse {
		return identity.ExitOK // no command dispatch and no go-ahead read, even if a sender supplies one
	}
	var goAhead [1]byte
	if _, err = io.ReadFull(rd, goAhead[:]); err != nil || goAhead[0] != 1 {
		return identity.ExitLauncher
	}
	_ = rd.Close()
	_ = wr.Close()
	ctx = context.WithValue(ctx, scopeKey{}, scopeInvocation{argv: in.Argv, once: true, outer: outer})
	return mainWith(ctx, in.Argv, stdout, stderr, commands())
}

func scopeCommand(argv []string, rehearse bool) bool {
	if len(argv) < 2 {
		return false
	}
	if argv[1] == "machine" {
		return len(argv) >= 3 && ((rehearse && argv[2] == "check") || (!rehearse && argv[2] == "test"))
	}
	if rehearse {
		return argv[1] == "doctor" || argv[1] == "setup" || argv[1] == "start"
	}
	return argv[1] == "run" || argv[1] == "watch" || argv[1] == "test"
}

func scopeReason(reason byte) error {
	switch reason {
	case 2:
		return errors.New("the re-entered command is not a user-scope command")
	case 3:
		return errors.New("the re-entered process cannot be shown to be outside every tego run")
	case 4:
		return errors.New("the re-entered process still cannot place a run in the user manager's cgroup")
	case 5:
		return errors.New("the caller's environment is invalid; no command was started")
	case 6:
		return errors.New("the re-entered process could not be made undumpable, and it holds the caller's environment")
	default:
		return errors.New("scope did not confirm placement")
	}
}

func scopeEnvironment(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, e := range in {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || strings.ContainsRune(e, 0) {
			return nil, scopeReason(5)
		}
		if !seen[k] {
			out = append(out, e)
			seen[k] = true
		}
	}
	return out, nil
}
