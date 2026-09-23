// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// maxTopologyBinaries bounds the binaries one run keeps a landlock-topology gap line for. Past it every
// refusal still gets its refused line and the gap is simply not repeated; an unsourced P0 default, like
// maxStandby.
const maxTopologyBinaries = 64

// topologySeen is the set of binaries a run already recorded a landlock-topology gap for (gapOwner's keys: a
// process stands for a binary that cannot be read). It is state
// about the ledger, not a decision input: every mount-family notification is answered the same way
// whatever it holds.
type topologySeen struct {
	mu   sync.Mutex
	seen map[string]bool
}

// first reports whether binary has no gap line yet in this run, and remembers it.
func (t *topologySeen) first(binary string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen[binary] || len(t.seen) >= maxTopologyBinaries {
		return false
	}
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	t.seen[binary] = true
	return true
}

// handleMount, handleUmount, handlePivotRoot and handleMoveMount answer the four syscalls through which a
// Landlock domain refuses a mount topology change (security/landlock/fs.c: sb_mount, sb_umount,
// sb_pivotroot, move_mount; SEMANTICS §10, docs/GAPS.md A9). Each reads the path it would change, for the
// record only: mount's target, umount2's and pivot_root's first argument, and move_mount's destination
// through its dirfd.
func handleMount(l *Loop, n *notif)     { l.refuseTopology(n, "mount", atFDCWD, n.args[1]) }
func handleUmount(l *Loop, n *notif)    { l.refuseTopology(n, "umount", atFDCWD, n.args[0]) }
func handlePivotRoot(l *Loop, n *notif) { l.refuseTopology(n, "pivot_root", atFDCWD, n.args[0]) }
func handleMoveMount(l *Loop, n *notif) {
	l.refuseTopology(n, "move_mount", int32(n.args[2]), n.args[3])
}

// handleUnshare, handleClone and handleSetns answer the namespace arm's notifications (enforce-landlock
// namespaceTest): an unshare or clone asking for a new mount or user namespace, and every setns. A new mount
// namespace is a copy of the mount tree with none of tier 2's fanotify marks on it, where a deny_read
// fanotify alone enforces was read with no permission event (docs/p0/enforce-cgroup-observe.md E24). They are
// refused
// with EPERM, the answer of a host that disallows unprivileged user namespaces, and recorded as
// landlock-topology, the reason SEMANTICS §10 gives a sandbox these tiers cannot host.
func handleUnshare(l *Loop, n *notif) { l.refuseTopologyAs(n, "unshare", namespaceFlags(n.args[0])) }
func handleClone(l *Loop, n *notif)   { l.refuseTopologyAs(n, "clone", namespaceFlags(n.args[0])) }
func handleSetns(l *Loop, n *notif) {
	l.refuseTopologyAs(n, "setns", "fd "+strconv.Itoa(int(int32(n.args[0]))))
}

// namespaceFlags names the namespace flags of an unshare or clone for the refused line's target.
func namespaceFlags(flags uint64) string {
	var names []string
	for _, f := range []struct {
		bit  uint64
		name string
	}{{unix.CLONE_NEWNS, "CLONE_NEWNS"}, {unix.CLONE_NEWUSER, "CLONE_NEWUSER"}, {unix.CLONE_NEWPID, "CLONE_NEWPID"},
		{unix.CLONE_NEWNET, "CLONE_NEWNET"}, {unix.CLONE_NEWUTS, "CLONE_NEWUTS"}, {unix.CLONE_NEWIPC, "CLONE_NEWIPC"},
		{unix.CLONE_NEWCGROUP, "CLONE_NEWCGROUP"}} {
		if flags&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	return strings.Join(names, "|")
}

// refuseTopology refuses one mount-family syscall with EPERM and records it: a refused line with
// reason landlock-topology, which the reason channel owes every refusal (REASON-CHANNEL §1, "every refusal
// is a refused event"), and gap what=enforce why=landlock-topology once per binary (gapOwner), which is how the run
// says that this tier cannot host the sandbox the agent tried to start (SEMANTICS §10).
//
// The answer is the one the kernel gives: both P0 tiers install a Landlock domain whose fs rights are
// always handled (enforce-landlock I4), and such a domain refuses these hooks with EPERM before any
// capability check (path_mount calls security_sb_mount before may_mount). Answering it here rather than
// continuing into Landlock's refusal makes the record certain instead of inferred, and costs nothing: the
// syscall could not have succeeded. An observe run has no domain: respond turns the errno into CONTINUE
// there (R30), and nothing was refused, so no line is written.
//
// The syscall name, not a contract entry, is what refused it, so the line carries rule unmatched: no entry
// a contract can write admits a mount in these tiers.
func (l *Loop) refuseTopology(n *notif, op string, dirfd int32, addr uint64) {
	r := l.newReader(n)
	target := r.path(dirfd, addr)
	if n.gone {
		return
	}
	l.refuseTopologyAs(n, op, target)
}

// refuseTopologyAs is refuseTopology once the target is known: a path, or the namespace flags of an unshare.
func (l *Loop) refuseTopologyAs(n *notif, op, target string) {
	binary, key := l.gapOwner(n)
	if n.gone {
		return
	}
	l.respond(n, respErrno(unix.EPERM))
	if l.observing() {
		return
	}
	if l.topology.first(key) {
		gap := l.event(n, record.KindGap, record.SourceSupervisor)
		l.emitFor(n, gap, record.GapPayload{What: record.GapEnforce, Why: string(record.ReasonLandlockTopology), Binary: binary, Count: 1})
	}
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = ruleUnmatched, record.ReasonLandlockTopology
	l.emitFor(n, ev, record.RefusedPayload{Op: op, Target: target, Reason: record.ReasonLandlockTopology, Rule: ruleUnmatched})
}

// gapOwner is who a once-per-binary gap line is written for: binary, the binary the notifying task runs, read
// from /proc/<tid>/exe inside an ID_VALID bracket (R2, E3: the tid could be reused once the notification is
// gone, and only the second check says the link was read from the task that trapped), and key, what a
// topologySeen set remembers the line under, the binary itself.
//
// When the link cannot be read, binary is "" and the line names none. That is a non-dumpable target's case
// (ssh-agent, gpg-agent): the kernel reads the link only past ptrace_may_access(PTRACE_MODE_READ_FSCREDS), the
// check that also answers its pidfd_getfd EPERM. key is then the process, "\x00pid <tgid>", which no path can
// spell, so each such process of the run gets its own line, carrying its pid, and its threads share it: keyed
// by the empty binary, every one of them shared the run's first line and the later ones went unrecorded. Nothing
// outside that check names the binary: comm and cmdline are
// the agent's to write. A process id the kernel reuses within the run shares its predecessor's line.
func (l *Loop) gapOwner(n *notif) (binary, key string) {
	if l.valid(n) {
		link, err := l.k.Readlink("/proc/" + strconv.Itoa(n.pid) + "/exe")
		if l.valid(n) && err == nil {
			binary = strings.TrimSuffix(link, deletedSuffix)
		}
	}
	if binary != "" {
		return binary, binary
	}
	return "", "\x00pid " + strconv.Itoa(l.tgidOfNotif(n))
}
