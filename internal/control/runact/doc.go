// SPDX-License-Identifier: Apache-2.0

// Package runact is what the dashboard does to a live run: Answer answers one held request as
// `tego approve <run> <ask_id>` and `tego deny <run> <ask_id>` do, and Stop stops a run as `tego stop <run>` does.
//
// Answer is the CLI's own client path: askclient.Launcher verifies the run's live launcher through its lock and keeps
// its pidfd open, and askclient.Answer dials <run>/ask.sock, refuses a server whose SO_PEERCRED pid is not that
// launcher's, answers the broker's nonce hello and sends the answer. The broker writes the answer line to the run's
// ledger before it replies, exactly as for the CLI.
//
// Stop is the smallest equivalent of internal/cli's runStop that tego-control may link (TestControlLinksNoEngine):
// the same lock probe and verified pidfd (runlock), the same stop marker placed by the same function
// (ledger.PlaceNewFileThen, the body of internal/runtime.RequestStopGraceThen) with no grace in it, so the launcher
// keeps the machine's stop_grace and records run_end reason=stopped, then SIGTERM through the pidfd. What it does
// not do: the orphan sweep, the release of an adoption, the cgroup.kill backstop after the
// grace (the launcher's own stop_grace timer still kills a run that does not end), and a root stop's rearm of tier-2
// build timers.
//
// Block and Blocks add, remove and list a running run's live blocks (internal/liveblock): the overlay in the run's
// directory, which the run's launcher polls and its supervisor enforces; the launcher records each change. Live lists
// them with the serial of each one's add, and Block returns the run's facts (StartFacts: watched or not, reads seen or
// not) and the overlay's serial, so a view says each block's state with internal/check/livestatus. A remove asked by a
// process inside a run is refused (SelfGoverned, governed.go): a governed agent may tighten a run, never loosen it.
// The run's own refusals (not running, a launcher too old for the change, reads not seen; for a lift or a restore a
// Locked run, an entry outside the fence, a key that cannot be read) are liveblock's checks and words
// (liveblock.CheckBlock, CheckFence, LiftKey), the ones `tego block`, `tego unblock`, `tego lift`, `tego grant` and
// `tego restore` make, so the dashboard and the terminal answer a change alike: a run that has ended is refused a
// block and a removal both, and its overlay is left as it was.
//
// Pause writes a pause or a resume into the same overlay for the launcher to apply (pause.go); it is refused to a
// caller inside a run, for a run that is not running, and for a run whose launcher did not mark that it reads one
// (liveblock.TakesControl: a run an older Tego started, an adopted run, one with no cgroup of its own).
//
// BlockUntil is Block with a time limit (ADR 0125 decision 4), refused on a run whose launcher does not read one
// (livestatus.Facts.Timed). Lift and Restore (lift.go) ask the launcher of an Adjustable run to allow, or refuse
// again, one of its fence entries: a lift carries a MAC under the run's key (liveblock.LiftKey) and is refused to a
// caller inside a run, to a Locked run and outside the fence; a restore narrows and is allowed from inside a run.
// Each writes a request only: the launcher decides what takes effect and records it.
//
// CheckLoosening (lift.go) is the refusal of the live switches outside the overlay, an MCP tool switch
// (internal/control/mcpact) and a model route (internal/control/routeact), before a change past the run's contract:
// liveblock.CheckLoosening on the run's lock and run_start. It refuses a run no launcher holds (ErrNotRunning) and a
// Locked run (ErrLocked, the words a Locked lift gets), and fails closed: a lock that cannot be probed counts as held,
// and a run_start that cannot be read yet is refused as not known (ErrStarting; ErrStartUnreadable when the first line
// is there and is not one this tego reads), never as Locked.
//
// Answer takes always as `tego approve|deny --always` does; Alternate is `tego alternate --file` (ADR 0057), with
// the CLI's symbolic-link-free opener ported here (internal/runtime/ask is not linkable) and an absolute path.
//
// Shortcut: no --grace from the dashboard.
//
// SelfGoverned (governed.go) is whether this process sits inside a run (runscope.InRun): a writer that would widen a
// run's governance refuses then with ErrGoverned. It fails closed: a cgroup it cannot judge (a cgroup namespace, an unreadable file)
// refuses too, since an agent could unshare a cgroup namespace to look like a container.
//
// Imports: the standard library, internal/askclient, internal/check/livestatus, internal/runlock, internal/ledger, internal/liveblock, internal/runscope, pkg/spec/askproto, pkg/spec/record, internal/platform/sys, golang.org/x/sys/unix.
// Must not import: the engine (internal/runtime, internal/policy, internal/bpf, internal/cli).
package runact
