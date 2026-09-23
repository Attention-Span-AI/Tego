// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// createRuleset builds the kernel object: one landlock_create_ruleset with the ABI's handled masks
// (R2, I4: the write side is always handled), then exactly one landlock_add_rule per held path with
// rights (I3) and one per net port rule (R6/R22). flags is always 0 (R20). A failure reports the
// offending entry (E21) and closes the ruleset fd, if it is still the ruleset (below).
//
// The kernel takes a path rule by descriptor number, so the rule lands on whatever file that number
// names during the call. Once every rule is in, each held number is checked to still name the file it
// was opened on (fdSet.owns), and a ruleset any of them fails is closed and never returned:
// a number some other code in the process closed and the kernel handed to its next open would have put
// that file's inode into the ruleset with the entry's rights. The ruleset's own number is then probed
// (rulesetStill), so no Handle carries a number that stopped naming a ruleset. The same checks run when a
// rule is refused, since the refusal may be the first sign of a lost number, and the ruleset number is
// closed on any failure only while it still answers as a ruleset (closeRuleset, I12).
func (bd *builder) createRuleset() (int, error) {
	attr := unix.LandlockRulesetAttr{Handled_access_fs: uint64(bd.profile.FS), Scoped: uint64(bd.profile.Scope)}
	if bd.netRestricted {
		attr.Handled_access_net = uint64(bd.profile.Net)
	}
	fd, err := bd.sc.CreateRuleset(&attr, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: landlock_create_ruleset(fs=%#x net=%#x scope=%#x): %w", ErrRulesetBuild, attr.Handled_access_fs, attr.Handled_access_net, attr.Scoped, err)
	}
	for _, p := range bd.fds.open {
		if p.Access == 0 {
			continue
		}
		pa := unix.LandlockPathBeneathAttr{Allowed_access: uint64(p.Access), Parent_fd: int32(p.FD)}
		if err := bd.sc.AddPathRule(fd, &pa, 0); err != nil {
			addErr := fmt.Errorf("%w: landlock_add_rule(%s %q, access %#x): %w", ErrRulesetBuild, kindName(p.Kind), p.Path, p.Access, err)
			return -1, errors.Join(addErr, bd.fds.verify(), closeRuleset(bd.sc, fd))
		}
	}
	for _, n := range bd.net {
		na := netPortAttr{AllowedAccess: uint64(n.Access), Port: uint64(n.Port)}
		if err := bd.sc.AddNetPortRule(fd, &na, 0); err != nil {
			addErr := fmt.Errorf("%w: landlock_add_rule(net port %d, access %#x): %w", ErrRulesetBuild, n.Port, n.Access, err)
			return -1, errors.Join(addErr, closeRuleset(bd.sc, fd))
		}
	}
	if err := bd.fds.verify(); err != nil {
		return -1, errors.Join(fmt.Errorf("%w: a rule may have landed on another file: %w", ErrRulesetBuild, err), closeRuleset(bd.sc, fd))
	}
	if err := rulesetStill(bd.sc, fd); err != nil {
		return -1, fmt.Errorf("%w: %w, so it is not closed again here", ErrRulesetBuild, err)
	}
	return fd, nil
}

// rulesetStill reports whether fd, the number landlock_create_ruleset gave, still names a Landlock
// ruleset. The anonymous inode every such file shares gives no (dev, ino) to compare, as
// fdSet.owns does, so the kernel is asked instead (ProbeRuleset). A number that answers any other way
// was closed, or closed and handed to another file, by something else in the process; EBADF alone
// does not say which, since the kernel's lookup answers it for an O_PATH file too. A number handed to
// another Landlock ruleset answers as this one would, and that is the limit of this check (I12): only
// kcmp(2) against a second reference held for the purpose could tell the two apart, and a kernel built
// without CONFIG_KCMP has no kcmp.
func rulesetStill(sc landlockSyscalls, fd int) error {
	err := sc.ProbeRuleset(fd)
	switch {
	case errors.Is(err, unix.ENOMSG):
		return nil
	case errors.Is(err, unix.EBADF):
		return fmt.Errorf("the ruleset fd %d is not open, or names an O_PATH file, not a Landlock ruleset (%w): something else in this process closed it, and an O_PATH open may have taken the number since", fd, err)
	case errors.Is(err, unix.EBADFD):
		return fmt.Errorf("the ruleset fd %d names a file that is not a Landlock ruleset (%w): something else in this process closed it and the number was reused", fd, err)
	}
	return fmt.Errorf("the ruleset fd %d did not answer as a Landlock ruleset (landlock_add_rule with no access: %v, want ENOMSG), so what it names is unknown", fd, err)
}

// closeRuleset closes fd only while it still names a Landlock ruleset (I12): any other number may be
// another owner's descriptor by now, and closing it would be the same fault, one owner closing a
// number another holds. That number is reported and left open.
func closeRuleset(sc landlockSyscalls, fd int) error {
	if err := rulesetStill(sc, fd); err != nil {
		return fmt.Errorf("%w, so it is not closed again here", err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close ruleset fd %d: %w", fd, err)
	}
	return nil
}

// Handle is the prepared, run-scoped state (§2): it owns the ruleset fd and every O_PATH fd until
// Close; the kernel domain the child installs from the ruleset lives on independently. Its method
// set is api.Handle plus enforce.Reporter; enforce hands it out behind those interfaces.
type Handle struct {
	sc         landlockSyscalls // Close probes the ruleset number through it (closeRuleset)
	rulesetFD  int              // -1 once released
	filter     []bpf.RawInstruction
	fds        *fdSet
	unenforced []string
	abi        int
	caps       backend.Set
	// filterOpts is what filter was assembled from, and ask whether the table has an fs ask entry: PlaneFilter
	// assembles the same filter less what a loaded plane decides.
	filterOpts filterOpts
	ask        bool
	listenHeld map[string]int
	snapshot   *Snapshot // the deny_read enumeration as Prepare froze it, nil when none (DenyReadSnapshot)
}

// LandlockRuleset returns the ruleset fd for landlock_restrict_self; ok is always true for this tier
// and fd is -1 after Close.
func (h *Handle) LandlockRuleset() (int, bool) {
	if h.fds == nil { // zero value (I7)
		return -1, true
	}
	return h.rulesetFD, true
}

// SeccompFilter returns the assembled program for seccomp(SET_MODE_FILTER, NEW_LISTENER); the
// caller must not mutate it.
func (h *Handle) SeccompFilter() ([]bpf.RawInstruction, bool) {
	if len(h.filter) == 0 {
		return nil, false
	}
	return h.filter, true
}

// NetworkGuarantees names only the client guards this filter installs. Landlock
// port rights never establish kernel destination admission by address.
//
// SocketFamilies is the filter's socket arm (ADR 0018 (1)): under a net: section it decides every socket(2) and
// socketpair(2) on their scalar arguments, in the kernel, and io_uring, the one other way a run makes a socket, is
// ENOSYS. A run whose io_uring a root tier's plane admits (Run.IOUring) makes sockets the filter never sees
// (IORING_OP_SOCKET), so the filter alone guarantees nothing there; enforce/cgroup adds the plane's socket_create.
func (h *Handle) NetworkGuarantees() backend.NetworkGuarantees {
	guarded := len(h.filter) != 0 && h.filterOpts.strictNet
	return backend.NetworkGuarantees{SocketImportsDenied: guarded, ListenersDenied: guarded && !h.filterOpts.listenersAllowed,
		SocketFamilies: len(h.filter) != 0 && h.filterOpts.socket.Restricted && !h.filterOpts.ioUring}
}

// PlaneFilter is SeccompFilter less the notifications the run's decision plane decides in the kernel, for a tier
// whose plane loaded and attached hooks, named as bpf.PlaneHook.Name names them (enforce-plane R22, R27;
// TIER3-PLAN T16): an fs mutation whose every form a loaded hook decides, the open family's write arm when
// file_open and path_mknod are loaded, and truncate(2) when path_truncate is. dropped names what was left out
// (the table's syscall names, with "open-write" and "truncate" for the two arms), empty when nothing was, and
// then prog is SeccompFilter's own. Nothing is left out with an fs ask entry, and under record: full the open
// family is kept (planeSkips).
// The caller decides whether the plane is live for this run; hooks it did not load keep their notifications.
func (h *Handle) PlaneFilter(hooks map[string]bool) (prog []bpf.RawInstruction, dropped []string, err error) {
	if len(h.filter) == 0 {
		return nil, nil, nil
	}
	skip := planeSkips(hooks, h.filterOpts.full, h.ask)
	if !skip.any() {
		return h.filter, nil, nil
	}
	o := h.filterOpts
	o.plane = skip
	if prog, err = assembleFilter(NativeArch(), o); err != nil {
		return nil, nil, err
	}
	t, err := tableFor(NativeArch())
	if err != nil {
		return nil, nil, err
	}
	for _, s := range t.Notify {
		if skip.names[s.Name] {
			dropped = append(dropped, s.Name)
		}
	}
	if skip.writeOpens {
		dropped = append(dropped, "open-write")
	}
	if skip.truncate && h.filterOpts.abi >= minTruncateABI {
		dropped = append(dropped, "truncate")
	}
	return prog, dropped, nil
}

// Attach is a no-op: tier 1 has no cgroup-keyed kernel state.
func (h *Handle) Attach(uint64) error { return nil }

// Detach is a no-op for the same reason.
func (h *Handle) Detach() error { return nil }

// Close releases every held fd and the ruleset fd, best effort with the errors joined; a second call
// is a no-op returning nil (I7). Only the launcher's bookkeeping is released. A held number that no
// longer names the file it was opened on, or a ruleset number that no longer names a ruleset, is
// reported and left open, not closed (closeAll, closeRuleset, I12).
func (h *Handle) Close() error {
	if h.fds == nil { // zero value or already closed (I7)
		return nil
	}
	errs := []error{h.fds.closeAll()}
	if h.rulesetFD >= 0 {
		errs = append(errs, closeRuleset(h.sc, h.rulesetFD))
	}
	h.rulesetFD = -1
	h.fds = nil
	return errors.Join(errs...)
}

// Capabilities is the run's own matrix: the backend's ABI-conditioned row with fs.deny_read cleared
// when any deny_read entry was left unenforced under a writable parent (R4).
func (h *Handle) Capabilities() backend.Set { return h.caps.Clone() }

// PlaneHeld is the held O_PATH descriptor of a path Prepare held under that name (Run.Plane's keyed paths among
// them): the decision plane's fill reads each keyed inode from it (enforce-plane R16). The handle keeps owning it;
// ok is false for a path it holds no descriptor for, one that did not exist included, and after Close.
func (h *Handle) PlaneHeld(path string) (int, bool) {
	if h.fds == nil {
		return -1, false
	}
	i, ok := h.fds.paths[path]
	if !ok || h.fds.open[i].FD < 0 {
		return -1, false
	}
	return h.fds.open[i].FD, true
}

// PlaneListenParent lends the declaration's dedicated held parent descriptor.
// It is identity-only; the parent's neutral rule is carried by PlaneHeld.
func (h *Handle) PlaneListenParent(path string) (int, bool) {
	if h.fds == nil {
		return -1, false
	}
	i, ok := h.listenHeld[path]
	if !ok || i < 0 || i >= len(h.fds.open) || h.fds.open[i].FD < 0 {
		return -1, false
	}
	return h.fds.open[i].FD, true
}
