// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Sink receives events from producers. Implementations must never block a producer for long: the pipeline
// buffers and counts drops (P0-DESIGN §2.4, §6).
type Sink interface {
	Emit(ev *record.Event)
}

// Source is a long-running producer of events owned by the run: the eBPF recorder, the uprobe capture, the
// forwarder. Start must return promptly and run its work in goroutines it stops on ctx cancel or Stop.
type Source interface {
	Name() string
	Start(ctx context.Context, run RunRef, sink Sink) error
	Stop() error
	// Gaps reports what this source could not cover for the run (fed into gap events at run_end).
	Gaps() []Gap
}

// LoopbackSource is a capture source the agent reaches over loopback instead of being observed through:
// the forwarder, whose listeners bind at construction so both facts below exist before the run is even
// started (docs/p0/capture-derive.md §3 "Forwarder listeners", R19).
//
// The run asks the source for them rather than taking a copy from its caller. An ephemeral port is the
// source's own fact, and the two places that need it — the agent's environment and the enforcement tier's
// net rules — must name the same port as the socket that is actually bound; a second copy handed in
// beside the source is the one that drifts.
type LoopbackSource interface {
	Source
	// Vars are the base-URL variables the run installs for the harness, keyed by variable name
	// (identity.Env.ForwarderVars, spec/identity/RUN-IDENTITY.md R7).
	Vars() map[string]string
	// Endpoints are the bound loopback addresses the enforcement tier must admit, because once
	// capture is active they are the agent's only route to the model (R38).
	Endpoints() []netip.AddrPort
}

// RunRef identifies the run for sources and the ledger.
type RunRef struct {
	ID    string
	Agent string
	// Dir is the run directory under the ledger root: the record, the lock and the blobs.
	Dir string
	// RuntimeDir is the run's tmpfs directory ($XDG_RUNTIME_DIR/tego/<run>), where a source may put
	// its files; "" when the machine has no XDG_RUNTIME_DIR. Removed when the run ends. The ask
	// broker's socket is not here but in Dir (ask.SocketName).
	RuntimeDir string
	CgroupID   uint64
	Contract   *agent.RuleTable
	// BlobBytes counts the bytes added to the run's blobs/ against record.max_run_bytes, for a source with a blob
	// store of its own; nil when the run has no ledger writer.
	BlobBytes *atomic.Int64
}

// Gap is one uncovered capability or capture path (spec/record/v1 gap payload).
type Gap struct {
	What   string // capture | record | enforce
	Why    string
	Binary string
	Count  int64
	// DecisionPlane is the plane's mode on a gap its counters gave (record.GapPlane*), "" on every other.
	DecisionPlane string
}

// ProcessHook is fed a run's process lifecycle as the tier's kernel record sees it: every exec, every open
// and every exit in the run's cgroups. It is how the uprobe capture source learns which processes to attach
// to and when to let go of them (docs/p0/capture-derive.md §4 "onExec driven by observe's exec stream", R4,
// R8). A hook is called on the recorder's drain goroutine, so it must return promptly; a capture source that
// follows the record is fed through a hookQueue, which calls it on a goroutine of its own.
type ProcessHook interface {
	// OnExec is one successful execve of pid in cgroup cgroupID. path is the file name the process passed
	// to execve, as the kernel's exec record copied it, or "" when the kernel's buffer truncated it; a
	// relative name comes joined to the process's working directory when the recorder could read that
	// directory as the one the exec used, and as passed otherwise (§2.4). It is what is left of
	// the image once a short-lived process has exited and taken /proc/<pid>/exe with it.
	OnExec(pid int, cgroupID uint64, path string)
	// OnOpen is one open of path by pid, the path as the kernel resolved it in the process's own
	// mount namespace.
	OnOpen(pid int, cgroupID uint64, path string)
	// OnExit is the exit of pid's thread group, when its last thread exits, once. It was the leader's exit,
	// which a leader that ends with pthread_exit makes while its threads go on (E23).
	OnExit(pid int)
}

// ProcessStream is a kernel recorder that can feed ProcessHooks. A hook is added before the recorder
// starts; one added after is refused with an error.
type ProcessStream interface {
	AddProcessHook(ProcessHook) error
}

// KernelFollower is a capture source that works off the tier's kernel objects rather than off the agent
// directly: it is told the build whose pins it loads its own object under and drains, and it is fed the
// kernel record's process stream. The uprobe source is the one there is.
type KernelFollower interface {
	ProcessHook
	// FollowKernel names the build, before Start, with the hash the enforcement handle pinned it under. An
	// empty hash withdraws the build again: the recorder that was to drive the follower reads nothing for
	// this run (recorderFirst), and a follower told no build captures nothing and says so when it starts.
	FollowKernel(bpfHash string)
}

// pairs is the process-wide source of Event.Pair tokens; zero is never handed out, and means unpaired.
var pairs atomic.Uint64

// NewPair returns a fresh pair token for the two lines of one captured exchange (Event.Pair).
func NewPair() uint64 { return pairs.Add(1) }

// MeteredSink is a Sink a capture source can also tell that model traffic went past it uncounted: an exchange
// on a model endpoint whose token spend capture could not read. The run's capture lane is one; a source asks
// for it through ReportUnmetered and never needs to know whether the run has a budget. What counts as
// uncounted is the source's call, listed in docs/p0/limits-check-doctor-cli.md
// R1: a successful answer whose usage could not be read (derive.Facts.Unmetered), the creation of a message
// batch, a response body capture lost before any usage was read, and an exchange lost with its connection.
type MeteredSink interface {
	Sink
	// Unmetered reports n exchanges whose spend no budget saw; why is the operator's detail.
	Unmetered(n int64, why string)
}

// ReportUnmetered tells sink that n model exchanges went uncounted, when sink listens for it. A sink that does
// not (a test's, a tier's recorder lane) is told nothing: the unparsed decision or gap the source records is
// the ledger's account of the loss either way.
func ReportUnmetered(sink Sink, n int64, why string) {
	if n <= 0 {
		return
	}
	if s, ok := sink.(MeteredSink); ok {
		s.Unmetered(n, why)
	}
}

// AbandonSink is a Sink a capture source can also tell that it gave up on a request's response: the pair
// token is the request's Event.Pair. The run's capture lane is one, and forwards it to the step tracker.
type AbandonSink interface {
	Sink
	// Abandoned says no ssl_response will come for pair.
	Abandoned(pair uint64)
}

// ReportAbandoned tells sink that pair's response will never come, when sink listens for it.
func ReportAbandoned(sink Sink, pair uint64) {
	if s, ok := sink.(AbandonSink); ok && pair != 0 {
		s.Abandoned(pair)
	}
}

// UnavailableCause is a capture source that can say why its mechanism is not running for this run, once its
// Start has recorded gap why=mechanism-unavailable (a capture object the kernel would not load, a capture ring
// the host's bpf.ring_budget had no room for, ADR 0026 (2)).
type UnavailableCause interface {
	UnavailableCause() string
}
