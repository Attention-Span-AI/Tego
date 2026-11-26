// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Argument is private process plumbing, never a user command.
const Argument = "__tego-draft-compile"

// Budget bounds all compilation work within one builder request: 3 s, times raceScale in a race build.
const Budget = 3 * time.Second * raceScale

// AdmissionWait bounds queueing when both compiler slots are occupied: 100 ms, times raceScale in a race build.
const AdmissionWait = 100 * time.Millisecond * raceScale

var slots = make(chan struct{}, 2)

// Request is one in-memory draft and the compile context already authorized by the service.
type Request struct {
	Directory *DirectoryRequest
	// ComposeOptions requests preset composition instead of compilation.
	ComposeOptions *setup.Options

	Machine             *config.Machine
	MachineSnapshot     *config.Snapshot
	Context             nextrun.Context
	Text                []byte
	Before              []byte
	Compare, SourceOnly bool
	// GrammarFingerprint is filled by Check from this executable's immutable
	// built-in grammar, never from dashboard form data.
	GrammarFingerprint string
}

// Result carries no environment values back as diagnostics. Canonical remains internal
// service data and is redacted before rendering.
type Result struct {
	Directory string
	// Composition retains setup metadata used to create the reviewed directories.
	Composition   *setup.Result
	Digest        string
	Sources       string
	Rows          []agentdiff.Result
	Repair        bool
	Relaxes       int
	BeforeRelaxes int
	Canonical     []byte
	Error         string
}

// readyMark is the first byte the child writes on its standard output: it has read the draft and is about to
// compile it. The check's compile budget starts when the parent reads it, so a busy machine's slow process start is
// the start-up allowance's and never the compiler's.
const readyMark = 1

// childOutput is the child's standard output: the ready mark, then the result.
type childOutput struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	seen  bool
	ready chan struct{}
}

func (o *childOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(p)
	if !o.seen && n > 0 {
		o.seen = true
		close(o.ready)
		if p[0] == readyMark {
			p = p[1:]
		}
	}
	o.buf.Write(p)
	return n, nil
}

func (o *childOutput) bytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Bytes()
}

// Check runs the compiler in a cancellable child. The process never holds fanotify
// marks; proc.Start independently refuses a start while this process is armed.
//
// The draft compile does not touch the location: inside a filesystem helper it pauses the helper's location clock
// for its whole time (contracts.PauseLocation), and has budgets of its own. The start-up allowance (StartAllowance)
// covers everything until the child has said it is about to compile; the compile budget (Budget) starts then. A check
// that ran out of either, or was cancelled, did not find a compile error: it returns contracts.CompileNotFinished,
// and nobody knows whether the contract compiles.
func Check(ctx context.Context, r Request) (Result, error) {
	ctx, resume := contracts.PauseLocation(ctx, StartAllowance+Cap)
	defer resume()
	c, err := beginCompilation(ctx)
	if err != nil {
		return Result{}, contracts.CompileNotFinished(err)
	}
	defer c.end()
	if err := c.exhausted(); err != nil {
		return Result{}, contracts.CompileNotFinished(err)
	}
	startCtx, cancelStart := c.startContext()
	defer cancelStart()
	// A governed program's request waits AdmissionWait for a slot and is then refused as busy; a person's own check
	// waits for one as long as its start-up allowance and its request allow, so a burst of governed requests that
	// fills the slots costs the person a wait, never the check (admissionWait).
	wait, admissionDeadline := admissionWait(ctx, startCtx)
	var admission <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		admission = timer.C
	}
	select {
	case slots <- struct{}{}:
	case <-startCtx.Done():
		return Result{}, contracts.CompileNotFinished(startCtx.Err())
	case <-admission:
		return Result{}, contracts.CompileUnavailable(true, errBusy)
	}
	if err := startCtx.Err(); err != nil {
		<-slots
		return Result{}, contracts.CompileNotFinished(err)
	}
	if r.Machine != nil && r.Directory == nil && r.ComposeOptions == nil && !r.SourceOnly {
		var err error
		r.GrammarFingerprint, err = builtinGrammarFingerprint(startCtx)
		if err != nil {
			<-slots
			if startCtx.Err() != nil {
				return Result{}, contracts.CompileNotFinished(startCtx.Err())
			}
			return Result{}, contracts.CompileUnavailable(false, errors.New("built-in grammar could not be bound"))
		}
	}
	if err := startCtx.Err(); err != nil {
		<-slots
		return Result{}, contracts.CompileNotFinished(err)
	}
	lease, err := compilerLease(startCtx, admissionDeadline)
	if err != nil {
		<-slots
		if startCtx.Err() != nil {
			return Result{}, contracts.CompileNotFinished(startCtx.Err())
		}
		return Result{}, contracts.CompileUnavailable(errors.Is(err, errBusy), err)
	}
	defer func() { _ = lease.Close() }()
	if r.Machine != nil {
		snapshot := r.Machine.Snapshot()
		r.MachineSnapshot = &snapshot
	}
	b, err := json.Marshal(r)
	if err != nil {
		<-slots
		return Result{}, contracts.CompileUnavailable(false, err)
	}
	cmd := proc.Command("/proc/self/exe", Argument)
	cmd.Stdin = bytes.NewReader(b)
	out := &childOutput{ready: make(chan struct{})}
	cmd.Stdout = out
	// Compiler diagnostics are encoded on stdout after scrubbing; no hidden value
	// can escape through a child runtime or loader message on stderr.
	cmd.Stderr = lease
	if _, err = proc.Start(cmd); err != nil {
		<-slots
		return Result{}, contracts.CompileUnavailable(false, fmt.Errorf("start draft compiler: %w", err))
	}
	done := make(chan error, 1)
	go func() { err := cmd.Wait(); <-slots; done <- err }()
	exited := false
	select {
	case <-out.ready:
	case err = <-done:
		exited = true
	case <-startCtx.Done():
		_ = cmd.Process.Kill() // Wait owns reaping, and retains the slot until it does.
		return Result{}, contracts.CompileNotFinished(fmt.Errorf("draft compiler did not start: %w", startCtx.Err()))
	}
	if !exited {
		var refused error
		if err, refused = awaitCompile(ctx, c, cmd, done); refused != nil {
			return Result{}, refused
		}
	}
	if err != nil {
		return Result{}, contracts.CompileUnavailable(false, fmt.Errorf("draft compiler stopped: %w", err))
	}
	var result Result
	if err = json.Unmarshal(out.bytes(), &result); err != nil {
		return Result{}, contracts.CompileUnavailable(false, errors.New("draft compiler returned an invalid result"))
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

// watchChild begins watching a compiler child's scheduler counters, a variable so a test can say what they read.
var watchChild = contracts.NewWatch

// awaitCompile waits for the compiler child to finish, within the compile budget, which starts now. When it runs out
// the kernel's counters for the child say why (contracts.Watch): starved of a CPU for at least half of the window, or
// on a CPU for at least half of it, and the child is given another Budget, until the request's cap; then it is refused
// as a check that did not finish because the machine is very busy (starved) or because the compile was still working
// (running). A child that was blocked, asleep, or could not be read is refused in words that claim no cause. The child
// is killed in every refusal; done is the exit of cmd, which retains
// the compiler slot until it is reaped. It returns the child's exit status, or why the check did not finish.
func awaitCompile(ctx context.Context, c *compilation, cmd *proc.Cmd, done <-chan error) (exit, refused error) {
	watch := watchChild(cmd.Process.Pid, 0)
	timer := time.NewTimer(c.startRun())
	defer timer.Stop()
	for {
		select {
		case err := <-done:
			return err, nil
		case <-ctx.Done():
			_ = cmd.Process.Kill() // Wait owns reaping, and retains the slot until it does.
			return nil, contracts.CompileNotFinished(fmt.Errorf("draft compilation stopped: %w", ctx.Err()))
		case <-timer.C:
			switch verdict := watch.Judge(); verdict {
			case contracts.Starved, contracts.Running:
				if step := c.grant(); step > 0 {
					timer.Reset(step)
					continue
				}
				_ = cmd.Process.Kill()
				if verdict == contracts.Running {
					return nil, contracts.CompileNotFinishedWorking(fmt.Errorf("draft compilation stopped: %w", context.DeadlineExceeded))
				}
				return nil, contracts.CompileNotFinished(fmt.Errorf("draft compilation stopped: %w", context.DeadlineExceeded))
			default:
				_ = cmd.Process.Kill()
				return nil, contracts.CompileNotFinishedUnclear(fmt.Errorf("draft compilation stopped: %w", context.DeadlineExceeded))
			}
		}
	}
}

// makeUndumpable is the one place this package sets PR_SET_DUMPABLE 0 on its own process, with a read-back
// (sys.MakeUndumpable). A variable so a test can fail it.
var makeUndumpable = sys.MakeUndumpable

// Helper handles the compiler child argument. Entrypoints call it before their
// normal command dispatch, and tests re-execute only their own test binary.
func Helper(args []string, in io.Reader, out io.Writer) (bool, int) {
	if len(args) != 2 || args[1] != Argument {
		return false, 0
	}
	// The child re-executes the program image, so it is dumpable again whatever its parent was (the dashboard is not).
	// It holds no key, but it is handed the draft and the machine's snapshot and answers what the Rules page shows, so a
	// process of the user that could attach to it could read the one and rewrite the other. It is made undumpable before
	// it reads either, and does not run when that cannot be done.
	if err := makeUndumpable(); err != nil {
		return true, 125
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(in, 4*agent.MaxContractSize)).Decode(&req); err != nil {
		return true, 125
	}
	// Say the draft is read and the compile is next; the parent's compile budget starts on this byte.
	if _, err := out.Write([]byte{readyMark}); err != nil {
		return true, 125
	}
	result := compile(req)
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return true, 125
	}
	return true, 0
}
func compile(req Request) Result {
	if req.Directory != nil {
		return checkDirectory(*req.Directory)
	}
	if req.ComposeOptions != nil {
		return composeRequest(*req.ComposeOptions)
	}
	m := req.Machine
	if req.MachineSnapshot != nil {
		m = req.MachineSnapshot.Restore()
	}
	if m == nil {
		return Result{Error: "no machine config to compile against"}
	}
	if m.Sources != nil {
		uid, _ := config.InvokingUID()
		if req.Context.Caller != nil {
			uid = req.Context.Caller.UID
		}
		var err error
		m, _, err = config.LoadSources(*m.Sources, m.Home, uid, config.TrustAbort)
		if err != nil {
			return Result{Error: "machine config could not be reloaded; check it in a terminal"}
		}
	}
	// The parent ends this child at its compile budget (Check) and says the compile did not finish. The child's own
	// bound is only for a parent that has gone, and is longer on purpose: a compile that ran out of time here would
	// be reported as a contract that does not compile.
	ctx, cancel := context.WithTimeout(context.Background(), 2*Budget)
	defer cancel()
	var rt, old *agent.RuleTable
	var err, oldErr error
	var oldProfiles, newProfiles []agent.ProfileUse
	if req.SourceOnly {
		c, _, loadErr := agent.LoadBytes(req.Context.Contract, req.Text, profileChain(m, req.Context.Caller))
		if loadErr != nil {
			return Result{Error: "the draft dependencies changed; review the new preview"}
		}
		newProfiles = c.Profiles()
		if req.Compare {
			c, _, loadErr = agent.LoadBytes(req.Context.Contract, req.Before, profileChain(m, req.Context.Caller))
			if loadErr == nil {
				oldProfiles = c.Profiles()
			}
		}
	} else {
		loaded, diagnostics, loadErr := agent.LoadBytes(req.Context.Contract, req.Text, profileChain(m, req.Context.Caller))
		if loadErr != nil {
			return Result{Error: redactLoadError(req.Text, nextrun.DiagError(diagnostics, loadErr).Error(),
				inheritedWhere(diagnostics, req.Context.Contract, m.Profiles.Value)...)}
		}
		rt, err = nextrun.CompileLoaded(ctx, m, req.Context, loaded)
		if err != nil {
			return Result{Error: redactLoadedError(req.Context, loaded, err.Error())}
		}
		newProfiles = rt.Profiles
		if req.Compare {
			loaded, _, oldErr = agent.LoadBytes(req.Context.Contract, req.Before, profileChain(m, req.Context.Caller))
			if oldErr == nil {
				oldProfiles = loaded.Profiles()
				old, oldErr = nextrun.CompileLoaded(ctx, m, req.Context, loaded)
			}
		}
	}
	sources, err := json.Marshal(struct {
		Machine       *config.Machine
		Before, After []agent.ProfileUse
	}{m, oldProfiles, newProfiles})
	if err != nil {
		return Result{Error: "dependency snapshot could not be bound"}
	}
	result := Result{Sources: fmt.Sprintf("%x", sha256.Sum256(sources))}
	if req.SourceOnly {
		return result
	}
	b, err := compiledBindingWithGrammar(result.Sources, old, rt, req.GrammarFingerprint)
	if err != nil {
		return Result{Error: "compiled snapshot could not be bound"}
	}
	canonical, err := rt.Contract.Canonical()
	if err != nil {
		return Result{Error: "compiled contract could not be described"}
	}
	result.Digest = fmt.Sprintf("%x", sha256.Sum256(b))
	result.Canonical = canonical
	result.Relaxes = len(rt.AskReadRelaxes)
	if req.Compare {
		result.Repair = oldErr != nil
		if old != nil {
			result.BeforeRelaxes = len(old.AskReadRelaxes)
		}
		if !result.Repair {
			result.Rows = agentdiff.Compare(old, rt)
		}
	}
	return result
}

func profileChain(m *config.Machine, caller *config.CallerContext) agent.ProfileSource {
	if caller != nil {
		return profilesrc.Chain(m, *caller)
	}
	return profilesrc.Chain(m)
}
