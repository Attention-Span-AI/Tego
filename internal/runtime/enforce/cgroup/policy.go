// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// policy is what the fanotify listener decides with: the run's cgroup subtree, the paths a contract denies
// reading, and the binaries it allows executing. It holds no fds and touches no kernel, so the decision this
// package makes per permission event is exercised entirely in unit tests.
//
// Why only these two decisions (docs/p0/enforce-cgroup-observe.md §5 R8): FAN_OPEN_PERM carries no access
// mode — the kernel reports that a file is being opened, not whether for reading or writing — so a listener
// cannot tell a write open from a read open and must not try. Write, delete, rename and mkdir denial is not
// this listener's: the inherited Landlock ruleset decides them by inode outside every write entry, and beneath a
// deny_read nested in a write entry the seccomp supervisor refuses them by the root walk at tier cgroup with no
// plane mode (supervisor fallbackMutation, ADR 0021 (5)), the decision plane where one runs. What
// fanotify adds is exactly what Landlock cannot express: a deny_read path that sits under a writable parent
// (enforce-landlock R3/R4 leaves those unenforced in tier 1), and an exec of a binary outside the allow-list,
// each refused with the precise reason the ledger records.
type policy struct {
	// runCgroup is the run's own cgroup path; the run is that path and everything nested under it.
	runCgroup string
	// denyRead holds the deny_read entries, indexed so the most specific one covering a path is found without
	// walking the others (pathSet).
	denyRead pathSet
	// readable holds the write entries, used only to keep a deny_read entry from swallowing a path the
	// contract grants explicitly and more specifically. A watch entry is not one: it grants nothing (SEMANTICS
	// §7), and filed here it reopened a deny_read Landlock leaves to this listener, a fail-open (R8).
	readable pathSet
	// execAllow holds the binaries and directories the contract permits executing, each under the path it
	// was compiled to and under that path with its symlinks followed. It is stored in the matcher's own shape
	// so a decision on the fanotify hot path allocates nothing.
	execAllow pathSet
	// execOpen is SEMANTICS §1's "no exec: section — deny nothing", read off the contract exactly as the
	// Landlock builder (execUnrestricted), the supervisor and decide.Evaluate read it: a table carrying a
	// contract whose Exec is nil. A hand-built table with no contract stays restricted, the fail-closed
	// reading all three take.
	execOpen bool
	// mounts lists one path per distinct mount the contract's rules touch; only these are marked. An
	// unruled filesystem is never marked and pays nothing (§5 R8).
	mounts []string
	// masks is the permission events each of mounts is marked for (markMasks): FAN_OPEN_PERM only where a
	// deny_read entry can refuse an open, FAN_OPEN_EXEC_PERM only where the exec check can refuse an exec.
	masks map[string]uint64
	// mountErr is the mount table that could not be read to list the mount points beneath a deny_read entry or a
	// name scope, wrapping ErrMountTable. Such a policy marks none of them, so Prepare refuses it (R8): a file on a
	// tmpfs mounted beneath the denied tree would otherwise be read with no event and no refusal.
	mountErr error
	// names is the table's name entries (ADR 0043 D7's fallback), indexed by the decision core: an open the path
	// entries allow is refused when one covers the opened file. Nil when the table has none.
	names *decide.NameIndex
	// aliasErr is a bind alias the listener cannot hold (ErrListenerAlias); Prepare refuses a run the listener decides.
	aliasErr error
	// listenerHeld says this listener decides a deny_read or a name entry. Such reads
	// refuse a setuid: true run in this release (ErrListenerSetuid).
	listenerHeld bool
	// openDevs is the devices of the mounts marked for opens, read from the same mount table as the marks: the
	// recorder's test of whether the listener saw a read (Handle.ListenerDevices). Nil where no device is known.
	openDevs map[uint64]struct{}
}

// fsEntry is one filesystem rule reduced to what a path decision needs.
type fsEntry struct {
	path string
	dir  bool
	rule string
}

// mountView is what a policy reads of the mount table: the mount points strictly beneath a directory (under), the
// other places the table shows a directory's tree at (aliases), each with the error that leaves them unknown, and the
// device of the mount a path reaches (device, nil where nothing is known of devices).
type mountView struct {
	under   func(string) ([]string, error)
	aliases func(string) ([]string, error)
	device  func(string) (uint64, bool)
}

// view is the snapshot's answers as a policy reads them.
func (s *mountSnapshot) view() mountView {
	return mountView{under: s.under, aliases: s.aliases, device: s.device}
}

// Limit startup diagnostics, not the checks: scanned name matches can contribute
// tens of thousands of path entries, each visible at many mounts.
const aliasDiagnosticEntries = 8
const aliasDiagnosticPlaces = 4

// newPolicyAt builds the listener inputs from prepared mount facts and the mount lookup.
// A test gives them without mount(2).
func newPolicyAt(rt *agent.RuleTable, runCgroup string, view mountView, mountOf func(string) (mountKey, error)) *policy {
	under, aliases := view.under, view.aliases
	p := &policy{runCgroup: runCgroup}
	if rt == nil {
		return p
	}
	var marks []markPath
	var denyRead, readable, execAllow []fsEntry
	var aliasDiagnostics []error
	aliasEntries := 0

	for i := range rt.FS {
		r := &rt.FS[i]
		if r.Path == "" {
			continue
		}
		// agent.FSRule.RuleName is the one spelling of a `rule` field: "fs.deny_read[~/.ssh]", not the bare
		// declared text and not a position (spec/record/v1/README.md, "the declared entry or unmatched").
		// The event this rule lands on is compared against the contract by `tego drift`, which registers
		// the declared side from the same method.
		//
		// Every entry covers a subtree: a directory obviously, and a single file harmlessly, since no path
		// can be nested under a file. A deny_read directory must not be readable through its children.
		//
		// The kernel reports the file it opened by its canonical path (readlink of the event's descriptor),
		// never by the symlinked name an author wrote, so each entry is also held under Resolved, the subtree
		// it governs (agent.FSRule): a deny_read on a symlinked ~/.aws was otherwise never matched here.
		var otherPlaces []string
		for _, path := range r.Spellings() {
			e := fsEntry{path: path, dir: true, rule: r.RuleName()}
			switch r.Kind {
			case agent.FSDenyRead:
				p.listenerHeld = true
				denyRead = append(denyRead, e)
				// Only a deny_read entry can make this listener refuse an open, so only its mount is worth
				// marking. A write entry takes part in a decision solely to reopen a path inside a denied tree,
				// which is on a mount the deny_read entry already marked.
				if r.Mount != "" {
					marks = append(marks, markPath{path: r.Mount, open: true})
				} else {
					marks = append(marks, markPath{path: e.path, open: true})
				}
				// A mark covers one mount, so a tmpfs or a second disk mounted beneath the denied tree raised
				// no event there, and Landlock leaves an entry nested in a write entry unenforced: a file on
				// such a submount was read with no refusal (R8; SEMANTICS §2, "a rule on /work
				// covers a tmpfs or a second disk mounted under it"). Every mount point beneath the entry is
				// marked too. One mounted after Prepare (an automount, a later mount by the host) is not.
				// A table that cannot be read lists none, and the policy carries the error for Prepare to refuse.
				mps, err := under(e.path)
				if err != nil && p.mountErr == nil {
					p.mountErr = fmt.Errorf("%w: the mount points beneath deny_read %s cannot be marked: %w", ErrMountTable, e.path, err)
				}
				for _, mp := range mps {
					marks = append(marks, markPath{path: mp, open: true})
				}
				// A path read back from an event cannot hold another name of this tree through
				// mutations. Refuse such a run when the listener would decide it (ADR 0011).
				als, err := aliases(e.path)
				if err != nil && p.mountErr == nil {
					p.mountErr = fmt.Errorf("%w: the other places of deny_read %s cannot be listed: %w", ErrMountTable, e.path, err)
				}
				otherPlaces = append(otherPlaces, als...)
			case agent.FSWrite:
				readable = append(readable, e)
			default:
				// Watch, implicit and built-in entries take part in no fanotify decision: a watch entry selects
				// what is recorded and grants nothing (SEMANTICS §7), an implicit one is a write guard.
			}
		}
		if len(otherPlaces) > 0 {
			aliasEntries++
			if len(aliasDiagnostics) >= aliasDiagnosticEntries {
				continue
			}
			slices.Sort(otherPlaces)
			otherPlaces = slices.Compact(otherPlaces)
			places := strings.Join(otherPlaces[:min(len(otherPlaces), aliasDiagnosticPlaces)], ", ")
			if extra := len(otherPlaces) - aliasDiagnosticPlaces; extra > 0 {
				places += fmt.Sprintf(", and %d more places", extra)
			}
			aliasDiagnostics = append(aliasDiagnostics, fmt.Errorf("%w: deny_read %s is also visible at %s; this tier's fanotify listener matches paths and cannot hold the rule through another name; remove those mounts", ErrListenerAlias, r.Path, places))
		}
	}
	if extra := aliasEntries - len(aliasDiagnostics); extra > 0 {
		aliasDiagnostics = append(aliasDiagnostics, fmt.Errorf("and %d more deny_read entries with other names", extra))
	}
	p.aliasErr = errors.Join(aliasDiagnostics...)
	p.execOpen = rt.ExecUnrestricted()
	// Under execOpen no exec decision can refuse, so no exec entry needs a matcher row or a mark.
	for i := range rt.Exec {
		r := &rt.Exec[i]
		if p.execOpen || r.Path == "" || r.Verdict != agent.VerdictAllow {
			continue
		}
		// Source ("command", "mcp:<name>", or the comma-joined "command,exec.allow" when one binary is
		// both) is provenance, not an entry anyone declared; RuleName names the entry (pkg/spec/agent evaluate.go).
		name := r.RuleName()
		// ExecRule.Path is absolute but keeps its symlinks (/bin/sh, /usr/bin/python3), and Interp is the
		// PT_INTERP string as the ELF spells it (/lib64/ld-linux-x86-64.so.2), while the kernel reports the
		// file it is about to execute by its canonical path (/usr/bin/dash, /usr/lib/x86_64-linux-gnu/...).
		// Matching the compiled strings alone refused every symlinked binary and every dynamic loader, and so
		// every dynamically linked command. The resolved form names the inode the inherited Landlock ruleset
		// grants EXECUTE to, since it opens each entry following its links (enforce-landlock R5). It is still
		// matched as a path, not by (device, inode): an inode match would also admit every other name of the
		// file, and uutils ships its applets as hard links of one binary, so `ls` would admit `rm` (§5 R8).
		for _, path := range agent.Spellings(r.Path, resolveNow(r.Path)) {
			execAllow = append(execAllow, fsEntry{path: path, dir: r.IsDir, rule: name})
			marks = append(marks, markPath{path: path})
		}
		if r.Interp != "" {
			for _, path := range agent.Spellings(r.Interp, resolveNow(r.Interp)) {
				execAllow = append(execAllow, fsEntry{path: path, rule: name})
				marks = append(marks, markPath{path: path})
			}
		}
	}

	// An Adjustable run's read fence entry was a deny_read entry, whose mount and the mount points beneath it a Locked
	// run marks, FAN_OPEN_EXEC_PERM included. Compile takes the entry out of rt.FS, so nothing marked them any more,
	// and an exec of a program there was never seen by decideExec: only Landlock and the supervisor's name check
	// (fenceReadExec, best effort) stood in its way. They stay marked for exec. No exec.allow entry
	// lies at, beneath or above a read entry (compile's liveRead), so decideExec refuses every exec there, lifted or
	// not, as in a Locked run. No open event is asked for: reads there are the live layer's, through held reads.
	if !p.execOpen && rt.Adjustable() {
		for _, e := range rt.Live.Entries {
			if e.Kind != agent.LiveKindRead || !filepath.IsAbs(e.Value) {
				continue
			}
			marks = append(marks, markPath{path: existingAncestor(e.Value)})
			mps, err := under(e.Value)
			if err != nil && p.mountErr == nil {
				p.mountErr = fmt.Errorf("%w: the mount points beneath live.fence.read %s cannot be marked: %w", ErrMountTable, e.Value, err)
			}
			for _, mp := range mps {
				marks = append(marks, markPath{path: mp})
			}
		}
	}

	// A name entry refuses opens anywhere beneath its scopes (ADR 0043 D7), so each scope's mount and every mount
	// point beneath it is marked for FAN_OPEN_PERM, as a deny_read entry's are, a dependency directory's mount
	// included (cheap: its opens are allowed). The listener reads back canonical paths, so the canonical scope is
	// what is marked and matched.
	p.names = decide.NewNameIndex(rt)
	if p.names != nil {
		seen := map[string]bool{}
		for i := range rt.NameDeny {
			for _, s := range rt.NameDeny[i].Scopes {
				if seen[s.Canonical] {
					continue
				}
				seen[s.Canonical] = true
				marks = append(marks, markPath{path: s.Canonical, open: true})
				mps, err := under(s.Canonical)
				if err != nil && p.mountErr == nil {
					p.mountErr = fmt.Errorf("%w: the mount points beneath the name scope %s cannot be marked: %w", ErrMountTable, s.Canonical, err)
				}
				for _, mp := range mps {
					marks = append(marks, markPath{path: mp, open: true})
				}
			}
		}
	}

	p.denyRead, p.readable, p.execAllow = newPathSet(denyRead), newPathSet(readable), newPathSet(execAllow)
	p.mounts, p.masks = markMasks(marks, p.denyRead, !p.execOpen, mountOf)
	p.listenerHeld = p.listenerHeld || p.names != nil
	// The devices of the mounts marked for opens, from the same table, for the recorder (Handle.ListenerDevices).
	if view.device != nil {
		p.openDevs = map[uint64]struct{}{}
		for _, m := range p.mounts {
			if p.masks[m]&unix.FAN_OPEN_PERM == 0 {
				continue
			}
			if dev, ok := view.device(m); ok {
				p.openDevs[dev] = struct{}{}
			}
		}
	}
	return p
}

// ErrListenerAlias is a run the listener would decide whose denied tree is also visible
// elsewhere. Prepare refuses it; the listener stores no alias decisions.
var ErrListenerAlias = errors.New("cgroup: fanotify cannot hold a deny_read tree visible under another name")

// ErrListenerSetuid is a run the fanotify listener would decide, with a deny_read
// entry or a name entry, under setuid: true: a setuid program the run starts can regain
// CAP_SYS_ADMIN and clone a mount tree with open_tree(2), whose copy no mark asks about (fix round 1, finding 5).
var ErrListenerSetuid = errors.New("cgroup: the fanotify listener cannot hold this contract's reads under setuid: true")

// existingAncestor is p, or its nearest ancestor that exists: the mount a program created at p later would be on.
// A deny_read entry names its mount through FSRule.Mount for the same reason; a fence entry carries no such field.
func existingAncestor(p string) string {
	for q := filepath.Clean(p); ; q = filepath.Dir(q) {
		if _, err := os.Stat(q); err == nil || q == "/" {
			return q
		}
	}
}

// mountPointsUnderFrom returns newPolicy's under: the mount points strictly beneath a directory, from the mount
// points read gives (the prepared snapshot's, MountSnapshot.Points: strict and parsed once). They are read on the
// first call only. The built-in .env scan puts one
// deny_read entry per .env file in the project tree (up to its 50,000-entry cap), and reading and parsing
// mountinfo again for each entry's every spelling made Prepare cost entries x mount lines, seconds on a host
// with many mounts. An unreadable table answers its read error on every call, never an empty list: no submount
// is marked then, and newPolicy's caller must refuse the run rather than enforce it quieter than its contract (R8, I7).
func mountPointsUnderFrom(read func() ([]string, error)) func(dir string) ([]string, error) {
	var (
		sorted  []string
		readErr error
		loaded  bool
	)
	return func(dir string) ([]string, error) {
		if !loaded {
			loaded = true
			points, err := read()
			if err != nil {
				readErr = err
			} else {
				sorted = slices.Clone(points)
				sort.Strings(sorted)
			}
		}
		if readErr != nil {
			return nil, readErr
		}
		return sortedUnder(sorted, dir), nil
	}
}

// sortedUnder lists the entries of a sorted mount point list strictly beneath dir, every one but "/" itself for the
// root (a name entry scoped to "/"). Every string with the prefix dir+"/" sits in one run of a sorted list, so a
// binary search finds the run.
func sortedUnder(sorted []string, dir string) []string {
	if dir == "" {
		return nil
	}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	var out []string
	for i := sort.SearchStrings(sorted, prefix); i < len(sorted) && strings.HasPrefix(sorted[i], prefix); i++ {
		if len(out) == 0 || out[len(out)-1] != sorted[i] {
			out = append(out, sorted[i]) // a path mounted over twice is one mount point to mark
		}
	}
	return out
}

// markPath is one path whose mount a rule needs marked, and whether the rule that put it there is a deny_read
// entry, the only kind that can refuse an open.
type markPath struct {
	path string
	open bool
}

// markMasks reduces the ruled paths to one mark per mount, as groupByMount does, and gives each mark only the
// permission events this listener can refuse on that mount (§5 R8):
//
//   - FAN_OPEN_PERM where an open on the mount can fall under a deny_read entry: the entry's own mount, and the
//     mount of any exec path an entry covers (a deny_read on /opt covers /opt/tools, a mount of its own, where
//     an exec entry marked it). decideOpen allows every open on any other marked mount, since no entry covers
//     a path there, so its event bought nothing but the opener's round trip through this listener.
//   - FAN_OPEN_EXEC_PERM on every marked mount while the exec check can refuse (execRestricted), and on none
//     under a contract with no exec: section, where decideExec allows every exec.
//
// Before this every mark carried both events. On a mount marked only for exec entries, the root filesystem in
// the KVM guest, where python3 lives, every open of every process was held for a decision that was always an
// allow: 20,000 opens in one run cost 0.3–0.7 s more than none at record: off and 1.7–2.7 s more at record:
// summary, against 30–40 ms for the same opens with no tego (docs/p0/enforce-cgroup-observe.md §9).
func markMasks(paths []markPath, denyRead pathSet, execRestricted bool, mountOfPath func(string) (mountKey, error)) ([]string, map[string]uint64) {
	for i := range paths {
		if !paths[i].open {
			_, paths[i].open = denyRead.match(paths[i].path)
		}
	}
	names := make([]string, len(paths))
	for i := range paths {
		names[i] = paths[i].path
	}
	groups := groupByMount(names, mountOfPath)
	masks := make(map[string]uint64, len(groups))
	var mounts []string
	for _, g := range groups {
		var mask uint64
		if execRestricted {
			mask |= unix.FAN_OPEN_EXEC_PERM
		}
		for _, i := range g.members {
			if paths[i].open {
				mask |= unix.FAN_OPEN_PERM
			}
		}
		if mask == 0 {
			continue // nothing can be refused there, so it is not marked at all
		}
		mounts = append(mounts, g.path)
		masks[g.path] = mask
	}
	sort.Strings(mounts)
	return mounts, masks
}

// resolveNow follows every symlink in path, at Prepare, which is when the inherited Landlock ruleset opens
// the same entry and pins the inode it resolves to; "" when the path does not resolve.
func resolveNow(path string) string {
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	return r
}

// mountKey names one mount, which is what a FAN_MARK_MOUNT mark is placed on: the mount id statx(2) reports
// for a path. unique says which id it is, since the two are separate numberings.
type mountKey struct {
	unique bool
	id     uint64
}

// errNoMountID is a statx that answered without either mount id: a kernel below 5.8, which is below the floor.
var errNoMountID = errors.New("cgroup: statx reported no mount id")

// mountKeyOf asks statx(2) which mount a path resides on, following symlinks as FAN_MARK_MOUNT does. It asks
// for STATX_MNT_ID_UNIQUE (6.8), which no mount ever reuses within a boot, and STATX_MNT_ID (5.8) together; a
// kernel that knows the first answers with it, and an older one ignores the bit it does not know. The
// reusable id names two mounts only when one is unmounted and another mounted between two calls of one
// Prepare, which then marks one mount too few; 6.8's unique id removes even that window.
func mountKeyOf(path string) (mountKey, error) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID|unix.STATX_MNT_ID_UNIQUE, &stx); err != nil {
		return mountKey{}, err
	}
	switch {
	case stx.Mask&unix.STATX_MNT_ID_UNIQUE != 0:
		return mountKey{unique: true, id: stx.Mnt_id}, nil
	case stx.Mask&unix.STATX_MNT_ID != 0:
		return mountKey{id: stx.Mnt_id}, nil
	default:
		return mountKey{}, errNoMountID
	}
}

// mountGroup is one mount a mark goes on: the path the mark is placed through, the first of the ruled paths
// that statx put on it, and the indexes of every ruled path it holds, so a caller can fold what each path's
// rule needs into the one mark.
type mountGroup struct {
	path    string
	members []int
}

// groupByMount groups ruled paths by the mount statx names for each, in the order the paths come, and keeps a
// path whose mount statx cannot name in a group of its own name (below). A path already
// looked up joins the group it was put in without a second statx: every deny_read entry of a rule table names
// its mount through the same path (FSRule.Mount), and the built-in .env scan can write 50,000 of them, which
// asked statx about one mount that many times.
//
// A mark is mount-scoped: FAN_MARK_MOUNT marks the one mount a path resides on, not the filesystem, so two
// paths are one mark only when statx(2) names one mount for both. The device number is not that test. Every
// bind mount of a filesystem shares its st_dev, and collapsing by device marked only the first of them: a
// deny_read entry under a bind of the root filesystem (/data bound from /srv/data) beside an exec entry on
// / left /data unmarked, and its refusals were never made there (§5 R8). A path whose mount statx cannot name
// is kept by name rather than dropped. On a kernel below 5.8, which reports no mount id, that at worst marks one
// mount twice, and marking is idempotent in the kernel; a path removed since compile (which refuses a missing
// deny_read or exec entry) fails its mark, and Prepare refuses the run rather than leave its mount unmarked.
//
// Exec rules contribute marks as well as fs rules. §5 R8 phrases the rule as "mounts holding an fs rule",
// but FAN_OPEN_EXEC_PERM is scoped the same way as FAN_OPEN_PERM: a binary on a mount nothing marked is
// simply never seen, and exec denial would silently do nothing on a contract whose fs rules and binaries live
// on different filesystems — /home and /usr being the ordinary case.
func groupByMount(paths []string, mountOfPath func(string) (mountKey, error)) []mountGroup {
	var out []mountGroup
	byMount := map[mountKey]int{}
	byName := map[string]int{}
	for i, p := range paths {
		if p == "" {
			continue
		}
		g, seen := byName[p]
		if !seen {
			g = -1
			if key, err := mountOfPath(p); err == nil {
				if m, dup := byMount[key]; dup {
					g = m
				} else {
					byMount[key] = len(out)
				}
			}
			if g < 0 {
				g = len(out)
				out = append(out, mountGroup{path: p})
			}
			byName[p] = g
		}
		out[g].members = append(out[g].members, i)
	}
	return out
}

// verdict is one fanotify decision: whether to let the open proceed, and, when not, the rule and reason the
// ledger event carries.
type verdict struct {
	allow bool
	// path is the file the kernel was about to open, as the ledger event reports it.
	path   string
	rule   string
	reason record.Reason
}

// allowed is the verdict for an open nothing objects to.
var allowed = verdict{allow: true}

// decideOpen decides a FAN_OPEN_PERM event by the decision core's listener rule (decide.ListenerOpen): a path
// under a deny_read entry is refused unless a more specific write entry names it, which is how a contract that
// denies a directory but names one file inside it keeps working. An open the path entries allow is refused when a
// name entry covers the opened file (decide.ListenerOpenName, ADR 0043 D7's fallback). Everything else is allowed:
// fanotify cannot see the access mode, so it never guesses.
func (p *policy) decideOpen(path string) verdict {
	if i, refused := decide.ListenerOpen(&p.denyRead.index, &p.readable.index, path); refused {
		return verdict{path: path, rule: p.denyRead.entries[i].rule, reason: record.ReasonReadDenied}
	}
	if rule, reason, refused := decide.ListenerOpenName(p.names, path); refused {
		return verdict{path: path, rule: rule, reason: reason}
	}
	return allowed
}

// decideExec decides a FAN_OPEN_EXEC_PERM event: a binary the contract did not name is refused. This is the
// path-aware half of exec denial (decide.ListenerExec); the inherited seccomp filter sees the syscall, Landlock sees the inode, and
// this sees the resolved path the kernel is about to execute. Under a contract with no exec: section it
// refuses none, as neither of the other two does (execOpen).
//
// The stage's own exec of the launcher happens before any mark exists (Arm arms after it, ADR 0021 (2)), so
// this sees only the agent's execs and refuses every one no entry names, tego's own binary included: there is
// no ignore mark and no admission by identity.
func (p *policy) decideExec(path string) verdict {
	if decide.ListenerExec(p.execOpen, &p.execAllow.index, path) {
		return allowed
	}
	// No entry covered the binary, so no entry can name the event: the schema's one non-entry value is
	// "unmatched" (spec/record/v1/README.md). "exec.allow" named a section, which is neither.
	return verdict{path: path, rule: agent.UnmatchedRule, reason: record.ReasonExecNotAllowed}
}

// canRefuse reports whether any path could be refused for an event of this kind: an exec under a contract with
// an exec list, an open under one with a deny_read entry or a name entry. decideEvent refuses an event whose path cannot be read
// back only where this holds, since where it does not, no path could have been refused.
func (p *policy) canRefuse(exec bool) bool {
	if p == nil {
		return false
	}
	if exec {
		return !p.execOpen
	}
	return len(p.denyRead.entries) > 0 || p.names != nil
}

// pathSet is a list of the listener's entries indexed by the decision core for one question: which entry is
// the most specific one covering a path (decide.PathIndex, which says why it is indexed rather than walked and
// what a lookup costs). An entry covers the path it names, and a directory entry covers every path beneath it
// as well, component by component, so "/a/bc" is never beneath "/a/b"; the most specific is the one with the
// longest path, the first listed of several naming one path.
type pathSet struct {
	entries []fsEntry
	index   decide.PathIndex
}

// newPathSet indexes entries in the order they were listed, which decides only one choice: between entries naming
// the same path, the first listed is the one a match returns (and so the rule a refusal names). The entries need no
// sort; the index finds the longest covering path whatever the order.
func newPathSet(entries []fsEntry) pathSet {
	keys := make([]decide.IndexEntry, len(entries))
	for i, e := range entries {
		keys[i] = decide.IndexEntry{Path: e.path, Dir: e.dir}
	}
	return pathSet{entries: entries, index: decide.NewPathIndex(keys)}
}

// match returns the most specific entry covering path, and false when none does (decide.PathIndex.Match).
func (s *pathSet) match(path string) (fsEntry, bool) {
	i, ok := s.index.Match(path)
	if !ok {
		return fsEntry{}, false
	}
	return s.entries[i], true
}
