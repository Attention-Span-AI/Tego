// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Mount is the cgroup2 mount point.
const Mount = identity.SystemCgroupRoot

// procSelfCgroup is the file that names the cgroup this process runs in.
const procSelfCgroup = "/proc/self/cgroup"

// Detect finds the cgroup root this process may create run cgroups under. Whoever asks, the mount
// must first be shown to be cgroup2 and to hold the cgroup /proc/self/cgroup names, with this
// process in it (case 39). A privileged process (effective uid 0 of the initial user namespace,
// config.InitNSRoot; ADR 0042 (5)(d): under `unshare -r` uid 0 owns no cgroup2 root) then uses the
// cgroup2 mount root, so its runs land at /sys/fs/cgroup/tego.slice/... (RUN-IDENTITY.md "Cgroup"; the
// systemd-delegation cost of that choice is §6 case 38). An unprivileged one uses the systemd user
// delegation user@<uid>.service: the one named by /proc/self/cgroup when the process runs inside it,
// else the canonical /sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service; a candidate
// qualifies when it is cgroup2fs and its cgroup.procs is writable. Every refusal of the mount or of
// the candidates is a *DetectError naming what could not be shown and the one fix for it, and
// matches ErrNotDelegated, except the uid-0 hierarchy refusal, which matches ErrNotCgroup2 and not
// ErrNotDelegated (with the statfs errno beside it when the mount point could not be statted at all);
// only NewAt's own stat of a root that has already qualified can fail otherwise.
func Detect(uid int) (*FS, error) {
	// A read failure yields nil, which names no cgroup, so no agreement can be shown and
	// requireMountAgreement refuses (case 39) instead of trusting the mount unverified.
	data, _ := os.ReadFile(procSelfCgroup)
	if config.InitNSRoot() {
		return privilegedRoot(Mount, data, os.Getpid())
	}
	return detectDelegated(Mount, data, uid, os.Getpid())
}

// CanPlace reports whether this process can put a process into a cgroup under Root, which is what a run
// does with its agent (clone3's CLONE_INTO_CGROUP) and what Detect does not ask (case 41). The kernel
// moves a process from one cgroup into another only for a writer of the cgroup.procs of the two
// cgroups' common ancestor ("Delegation Containment", Documentation/admin-guide/cgroup-v2.rst), and
// CLONE_INTO_CGROUP asks the same of the parent's cgroup and the child's. A process inside the root has
// that ancestor inside the root too, in the subtree delegated to its uid. One that runs beside it has the
// ancestor above the delegation: under systemd, user-<uid>.slice or the cgroup2 root, both root's. A login
// over ssh runs in its session-<n>.scope and a service in system.slice, so either finds its
// user@<uid>.service delegated, writable and usable for every other operation (Create, SetLimits, Kill,
// the sweep's and stop's kills), and cannot place an agent in it. A privileged root is the mount root,
// the ancestor of every cgroup, and uid 0 may write its cgroup.procs, so it can always place. Every
// refusal is a *DetectError matching ErrOutsideSubtree and the errno.
func (fs *FS) CanPlace() error {
	if fs.privileged {
		return nil
	}
	// A read failure yields nil, which names no cgroup, and canPlace refuses it.
	data, _ := os.ReadFile(procSelfCgroup)
	return canPlace(Mount, data, fs.root, placementRemedy)
}

// PlacementFix is the remedy for a launcher of uid started outside the delegated subtree: start it from a shell inside.
// `systemd-run --user --scope bash` opens one from any shell of the same user whose user manager it can reach, since
// the user manager has the system manager move the caller into a new scope of its own subtree. The fix names the
// shell to open, not the cgroup's path: a new user read the path as the instruction, and the old "tego ..." was a
// placeholder outside angle brackets (acceptance B, 2026-11-11). The path stays in the diagnosis. When the person who
// reads it is another user, who started tego as uid through sudo or su (other, config.StartedByAnother), the shell is
// opened as uid from that person's own shell (ScopeAsCommand): typed there, the bare command opens the reader's own
// scope, the silent wrong-user result the next: line no longer gives (acceptance 3, 2026-11-11; the review's M1: the
// fix: line of doctor and the error of run, watch and test still said the bare command after linger).
func PlacementFix(uid int, other bool) string {
	if other {
		return "start tego from a shell in this user's user manager's cgroup: tego ran as this user, started from " +
			"another user's shell through sudo or su, so open one as this user from your own login shell, not one sudo " +
			"or su opened, with " + ScopeAsCommand(uid, "bash") + ", then run tego there"
	}
	return "start tego from a shell in your user manager's cgroup: open one with systemd-run --user --scope bash, " +
		"then run tego there"
}

// placementRemedy is PlacementFix for this process: its real uid (a delegated FS is never root's), and whether the
// person who reads the remedy is another user (readByAnother). It is asked only when CanPlace refuses.
func placementRemedy() string { return PlacementFix(os.Getuid(), readByAnother()) }

// readByAnother is config.ReadByAnother; a variable so a test is read by another user.
var readByAnother = config.ReadByAnother

// canPlace is CanPlace against an explicit mount, /proc/self/cgroup content and root, so a process can
// drive the refusal over a temporary directory without being where it is about. fix is the placement refusal's
// remedy, asked only for that refusal.
func canPlace(mount string, procCgroup []byte, root string, fix func() string) error {
	own := ownCgroup(procCgroup)
	if own == "" {
		return refuse(fmt.Sprintf("run tego where %s is readable", procSelfCgroup), []error{ErrOutsideSubtree},
			"%v: %s names no cgroup v2 (0::) path for this process, so it cannot be shown to lie inside %s",
			ErrOutsideSubtree, procSelfCgroup, root)
	}
	from := path.Join(mount, own)
	if from == root || strings.HasPrefix(from, root+"/") {
		return nil
	}
	anc := commonAncestor(from, root)
	if err := unix.Access(path.Join(anc, fileProcs), unix.W_OK); err != nil {
		return refuse(fix(), []error{ErrOutsideSubtree, ErrBesideSubtree, err},
			"%v: this process's cgroup %s lies outside %s, and the kernel moves a process between the two only "+
				"for a writer of %s/%s, their common ancestor's (cgroup v2 delegation containment): %v",
			ErrOutsideSubtree, from, root, anc, fileProcs, err)
	}
	return nil
}

// commonAncestor returns the deepest directory that holds both a and b, two clean absolute paths. Pure
// over its input.
func commonAncestor(a, b string) string {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] {
		n++
	}
	if n <= 1 {
		return "/"
	}
	return strings.Join(as[:n], "/")
}

// hierarchyFix is the remedy for a mount that is not cgroup2 at all.
func hierarchyFix(mount string) string {
	return fmt.Sprintf("mount the cgroup v2 hierarchy at %s (on a systemd host, boot with "+
		"systemd.unified_cgroup_hierarchy=1)", mount)
}

// delegationFix is the remedy for an agreeing mount with no writable user@<uid>.service in it.
const delegationFix = "enable systemd user delegation (Delegate=cpu memory pids in " +
	"/etc/systemd/system/user@.service.d/delegate.conf, then systemctl daemon-reload and re-login)"

// detectDelegated is Detect's unprivileged branch against an explicit mount, /proc/self/cgroup
// content and pid, so the case-39 refusal can be driven without being in the namespace it is about.
//
// The mount's own magic comes first. Every candidate is a path under mount and every case-39
// question is a read of mount's cgroup.procs files, so when mount is not a cgroup2 filesystem
// neither answer means anything: on a cgroup v1 or hybrid host /sys/fs/cgroup is a tmpfs holding
// no cgroup.procs at all, so without this check requireMountAgreement would refuse and blame the
// namespaces, when the fix is the hierarchy itself. The refusal matches ErrNotDelegated and wraps
// checkCgroup2's error: ErrNotCgroup2 when the mount has the wrong magic, the statfs errno when the
// mount point cannot be statted at all (absent, for one). Either way its Remedy is the hierarchy.
func detectDelegated(mount string, procCgroup []byte, uid, pid int) (*FS, error) {
	if err := checkCgroup2(mount); err != nil {
		return nil, refuse(hierarchyFix(mount), []error{ErrNotDelegated, err}, "%v: %v", ErrNotDelegated, err)
	}
	candidates, err := candidatesIn(mount, procCgroup, uid, pid)
	if err != nil {
		return nil, err
	}
	return firstWritableIn(mount, uid, candidates)
}

// firstWritableIn is firstWritable under mount, with one cause told apart (ErrNoUserManager): the only candidate is
// the canonical user@<uid>.service, it does not exist, and mount holds systemd's user.slice. Then no user manager runs
// for uid, as for an account with a nologin or false shell reached through su or sudo -u that never logged in and has
// no linger (acceptance 2B, 2026-11-11, Ubuntu 24.04, AlmaLinux 9.8, Fedora 44). The delegation fix changes nothing
// there; starting that user's manager does. Anything else keeps firstWritable's refusal.
func firstWritableIn(mount string, uid int, candidates []string) (*FS, error) {
	fs, err := firstWritable(uid, candidates)
	if err == nil {
		return fs, nil
	}
	canonical := canonicalSubtreeIn(mount, uid)
	if len(candidates) != 1 || candidates[0] != canonical {
		return nil, err
	}
	if _, serr := os.Stat(canonical); !errors.Is(serr, os.ErrNotExist) {
		return nil, err
	}
	if fi, serr := os.Stat(path.Join(mount, "user.slice")); serr != nil || !fi.IsDir() {
		return nil, err
	}
	return nil, refuse(NoManagerFix(uid), []error{ErrNotDelegated, ErrNoUserManager, os.ErrNotExist},
		"%v for uid %d: no user manager runs for uid %d: %s does not exist (user@%d.service is not running, as for an "+
			"account that has not logged in and has no linger)", ErrNotDelegated, uid, uid, canonical, uid)
}

// NoManagerFix is the remedy when no user manager runs for uid (ErrNoUserManager): an administrator starts it so that
// it runs without a login (LingerCommand), then opens a shell in it as that user (ScopeAsCommand) and runs tego there.
// The administrator types both in their own shell: the scope command written without sudo -u opened the
// administrator's own scope on Ubuntu 24.04 and AlmaLinux 9.8, where tego setup then said ready for the wrong user,
// and failed on Fedora 44 (acceptance 3, 2026-11-11); with it, it was ready at tier 1 on all three. When systemd
// refuses the account's name (ManagerRefused), linger starts no manager, so the remedy names neither command and says
// what can be done instead. Every word is fixed or comes from uid and its passwd entry, never from the environment.
func NoManagerFix(uid int) string {
	if why := ManagerRefused(uid); why != "" {
		return why + ", so loginctl enable-linger starts none and tego starts no run for this account: an administrator " +
			"runs the agent as an account whose name starts with a letter and holds only letters, digits, '_' and '-'"
	}
	return fmt.Sprintf("start a user manager for this user that runs without a login: an administrator runs %s; then "+
		"opens a shell in it as this user, from the administrator's own shell, with %s, and runs tego there",
		LingerCommand(uid), ScopeAsCommand(uid, "bash"))
}

// ManagerRefused is why systemd starts no user manager for uid, whose name in the passwd entry it refuses
// (config.SystemdRefusedName: digits only, which it reads as a uid, among others), as a sentence; "" when there is no
// entry or systemd accepts the name. The name is said only when every character of it prints.
func ManagerRefused(uid int) string {
	name, ok := lookupName(uid)
	if !ok {
		return ""
	}
	why := config.SystemdRefusedName(name)
	if why == "" {
		return ""
	}
	said := "the name of uid " + strconv.Itoa(uid)
	if name != "" && strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		said += ", " + shellword.Quote(name) + ","
	}
	return "systemd starts no user manager for this account: " + said + " " + why + " (systemd.io/USER_NAMES)"
}

// LingerCommand is the command that starts uid's user manager at boot and keeps it running without a login: sudo
// loginctl enable-linger and the user's name from the passwd entry (config.LookupPasswd, never $USER), as one quoted
// word, or the uid itself, which loginctl takes too, when there is no entry, the name holds a character that does not
// print, or loginctl would not read the name as a name: one that starts with '-' is an option to it, quoted or not,
// and one of digits only is a uid (the review's S4; config.PlainUserName).
func LingerCommand(uid int) string {
	word := strconv.Itoa(uid)
	if name, ok := lookupName(uid); ok && config.PlainUserName(name) {
		word = shellword.Quote(name)
	}
	return "sudo loginctl enable-linger " + word
}

// ScopeAsCommand is the command that opens a shell (one of fixed words, such as bash) in uid's user manager's cgroup as
// that user, typed by another user who may use sudo: sudo -u, the user's name from the passwd entry as one quoted word
// ('#<uid>' when there is none or sudo would not read it as itself, config.PlainUserName), then
// XDG_RUNTIME_DIR=/run/user/<uid>, where logind keeps that manager's sockets, since sudo -u leaves it unset and
// systemd-run --user connects through it. Measured on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44 (acceptance 3,
// 2026-11-11, GUEST-CHECK row 7b): a shell in that user's manager, where tego setup was ready at tier 1.
func ScopeAsCommand(uid int, shell string) string {
	word := "'#" + strconv.Itoa(uid) + "'"
	if name, ok := lookupName(uid); ok && config.PlainUserName(name) {
		word = shellword.Quote(name)
	}
	return "sudo -u " + word + " XDG_RUNTIME_DIR=" + path.Join(config.LogindRuntimeRoot, strconv.Itoa(uid)) +
		" systemd-run --user --scope " + shell
}

// lookupName is uid's name in the passwd database (config.LookupPasswd); a variable so a test names its users.
var lookupName = func(uid int) (string, bool) {
	u, err := config.LookupPasswd(uid)
	if err != nil {
		return "", false
	}
	return u.Username, true
}

// candidatesIn is the ordered list of roots detectDelegated tries under a mount already known to
// be cgroup2: the user@<uid>.service that /proc/self/cgroup names, when the mount agrees with that
// name, then the canonical one. It refuses instead when the mount has not been shown to agree,
// because the canonical candidate is spliced onto the same mount (see requireMountAgreement). It
// touches the mount only through reads of cgroup.procs, so the default test tier drives it over a
// temporary directory.
func candidatesIn(mount string, procCgroup []byte, uid, pid int) ([]string, error) {
	var candidates []string
	if sub := delegatedCandidate(mount, procCgroup, uid, pid); sub != "" {
		candidates = append(candidates, sub)
	} else if err := requireMountAgreement(mount, procCgroup, pid); err != nil {
		return nil, err
	}
	// Inside the canonical user@<uid>.service the two are one path; listing it twice would only
	// repeat it in the refusal's "tried" list.
	if canonical := canonicalSubtreeIn(mount, uid); len(candidates) == 0 || candidates[0] != canonical {
		candidates = append(candidates, canonical)
	}
	return candidates, nil
}

// firstWritable returns a manager over the first candidate that qualifies, or ErrNotDelegated
// naming every candidate tried, the last reason, and the delegation fix.
func firstWritable(uid int, candidates []string) (*FS, error) {
	var last error
	for _, root := range candidates {
		if err := writable(root); err != nil {
			last = err
			continue
		}
		return NewAt(root)
	}
	return nil, refuse(delegationFix, []error{ErrNotDelegated}, "%v for uid %d (tried %s): %v",
		ErrNotDelegated, uid, strings.Join(candidates, ", "), last)
}

// requireMountAgreement is case 39's refusal, and it is asked of the *mount*, not of one
// candidate. Agreement between /proc/self/cgroup and the cgroup2 filesystem at mount is a single
// fact about that filesystem: if it does not hold the cgroup this process is in, then every path
// spliced onto it names someone else's tree — the canonical
// user.slice/user-<uid>.slice/user@<uid>.service included. Checking it only where the derived
// candidate is built leaves the case that motivated it wide open, because the shape it describes
// does not produce a derived candidate at all: a cgroupns-private container reads "0::/" for its
// own namespace root (cgroup_namespaces(7)), which carries no user@<uid>.service segment, so
// delegatedCandidate declines for the ordinary reason and the canonical path in the host's tree
// would be next.
//
// nil means agreement was shown: procCgroup's unified path resolves under mount to a cgroup whose
// cgroup.procs lists pid. Everything else is a refusal, since a mount whose agreement is merely
// unknown is the mount case 39 is about. That includes the two ways of having nothing to compare.
// A unified path ownCgroup will not resolve is the first: cgroup_namespaces(7) prints "../" entries
// when the process's cgroup lies outside the reader's namespace root, so the cgroup has no name
// under that root and no path spliced onto the mount can be shown to be it. No unified line at all
// is the second. The caller has already shown mount is cgroup2, and the kernel lists the unified
// hierarchy in every /proc/<pid>/cgroup once a cgroup2 filesystem is mounted, so on a real host
// that is a /proc/self/cgroup that could not be read, not a host without cgroup v2.
func requireMountAgreement(mount string, procCgroup []byte, pid int) error {
	raw, ok := unifiedPath(procCgroup)
	if !ok {
		return refuse(fmt.Sprintf("run tego where %s is readable", procSelfCgroup), []error{ErrNotDelegated},
			"%v: %s names no cgroup v2 (0::) path for this process (unreadable, or no 0:: line), so %s "+
				"cannot be shown to hold its cgroup (case 39)", ErrNotDelegated, procSelfCgroup, mount)
	}
	own := ownCgroup(procCgroup)
	if own == "" {
		return refuse(fmt.Sprintf("run tego from a cgroup inside its own cgroup namespace, with that "+
			"namespace's cgroup2 mount at %s", mount), []error{ErrNotDelegated},
			"%v: %s names this process's cgroup as %q, which is not an absolute path inside this cgroup "+
				"namespace (a ../ entry means the cgroup lies outside the namespace root, cgroup_namespaces(7)), "+
				"so %s cannot be shown to hold it (case 39)", ErrNotDelegated, procSelfCgroup, raw, mount)
	}
	if mountAgrees(mount, own, pid) {
		return nil
	}
	return refuse(fmt.Sprintf("give this cgroup namespace its own cgroup2 mount at %s instead of the "+
		"host's tree", mount), []error{ErrNotDelegated},
		"%v: %s puts this process in cgroup %q, but %s holds no such cgroup with this process in its %s, "+
			"so the two name different cgroup trees and every path under %s belongs to someone else (case 39)",
		ErrNotDelegated, procSelfCgroup, own, mount, fileProcs, mount)
}

// privilegedRoot is Detect's uid-0 branch: the cgroup2 mount root itself, against an explicit mount,
// /proc/self/cgroup content and pid so both of its refusals can be driven without root. The magic
// check is the same D3 half writable() applies to every unprivileged candidate, and it is not
// redundant for root: a uid-0 launcher on a cgroup v1 or hybrid host would otherwise get an FS over
// a tmpfs, mkdir plain directories in it, find no control files at all, and only discover that when
// clone3(CLONE_INTO_CGROUP) refuses the fd or cgroup.kill turns out not to exist — i.e. after the
// run was allowed to start with no cgroup enforcement behind it. Refusing here keeps the failure
// before anything is created and gives the operator ErrNotCgroup2 instead of a downstream errno.
// That includes a mount point statfs cannot reach at all (absent, for one): no cgroup2 filesystem is
// there either, and the cure is the same hierarchy, so the refusal wraps ErrNotCgroup2 beside the
// errno and its diagnosis begins with ErrNotCgroup2's text, as every Detect refusal begins with its
// sentinel's (DetectError.Diagnosis).
//
// Case 39's agreement is asked here too, because root's mount can be someone else's tree exactly
// as an unprivileged launcher's can: a uid-0 launcher in a cgroupns-private container handed the
// host's /sys/fs/cgroup reads "0::/" for its own namespace root, and without the check it would
// mkdir tego.slice and write limit files in the host's root cgroup before clone3 failed (with
// nsdelegate, CLONE_INTO_CGROUP outside the namespace is ENOENT even for root). Being root gives no
// knowledge of which tree the mount is.
func privilegedRoot(mount string, procCgroup []byte, pid int) (*FS, error) {
	if err := checkCgroup2(mount); err != nil {
		if !errors.Is(err, ErrNotCgroup2) {
			err = fmt.Errorf("%w: %w", ErrNotCgroup2, err)
		}
		return nil, refuse(hierarchyFix(mount), []error{err}, "%v", err)
	}
	if err := requireMountAgreement(mount, procCgroup, pid); err != nil {
		return nil, err
	}
	fs, err := NewAt(mount)
	if err != nil {
		return nil, err
	}
	fs.privileged = true
	return fs, nil
}

// delegatedCandidate is the /proc/self/cgroup-derived root Detect tries before the canonical one,
// or "" when it must not be trusted. The path in /proc/<pid>/cgroup is relative to the *reading*
// process's cgroup namespace root (cgroup_namespaces(7): "the pathname shown ... will be relative
// to the reading process's root directory"), while mount is a fixed path, so splicing one onto the
// other is only meaningful when the two agree — systemd states that agreement as a requirement
// ("path consistency with /proc/$PID/cgroup is mandatory", systemd.io/CGROUP_DELEGATION). Where
// they do not agree (a cgroupns-private container whose /sys/fs/cgroup is the host's tree, not the
// namespace's) the splice names a real, writable, *different* subtree, and Tego would build run
// cgroups in someone else's. mountAgrees vetoes that splice here.
//
// This is the per-candidate half of the rule only. The disagreement it detects condemns the whole
// mount, not this candidate, so on "" candidatesIn asks the same question of the mount in
// requireMountAgreement, which turns the silent wrong answer into ErrNotDelegated; "" on its own
// means no more than "no derived candidate here".
func delegatedCandidate(mount string, procCgroup []byte, uid, pid int) string {
	sub := delegatedSubtreeIn(mount, procCgroup, uid)
	if sub == "" {
		return ""
	}
	if !mountAgrees(mount, ownCgroup(procCgroup), pid) {
		return ""
	}
	return sub
}

// mountAgrees reports whether the cgroup2 filesystem mounted at mount is the one own was written
// against: it resolves own under mount and looks for pid in that cgroup's cgroup.procs, which
// cgroups(7) documents as "a list of the processes that are members of a cgroup" and which
// cgroupfs publishes 0644. A process is always a member of its own cgroup, so a listing that does
// not contain pid means the mount and /proc/self/cgroup describe different trees. Unreadable
// (wrong tree, so the path may not even exist) counts as disagreement.
func mountAgrees(mount, own string, pid int) bool {
	if own == "" {
		return false
	}
	data, err := os.ReadFile(path.Join(mount, own, fileProcs))
	if err != nil {
		return false
	}
	return hasPID(data, pid)
}

// hasPID reports whether a cgroup.procs listing contains pid. The file is one pid per line and
// may hold duplicates or stale entries (cgroups(7)); only membership is asked. Pure over its input.
func hasPID(data []byte, pid int) bool {
	want := strconv.Itoa(pid)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if string(bytes.TrimSpace(line)) == want {
			return true
		}
	}
	return false
}

// unifiedPath returns the path of the first "0::" line in a /proc/<pid>/cgroup file, unvalidated,
// and whether there is such a line. Only the unified "0::" line counts; v1 lines are ignored. It is
// separate from ownCgroup because requireMountAgreement must tell "no unified line" from "a unified
// line ownCgroup refused" to say which one it refused. Pure over its input.
func unifiedPath(procCgroup []byte) (string, bool) {
	for _, line := range bytes.Split(procCgroup, []byte{'\n'}) {
		if rest, ok := bytes.CutPrefix(line, []byte("0::")); ok {
			return string(rest), true
		}
	}
	return "", false
}

// ownCgroup returns the cgroup v2 path recorded in a /proc/<pid>/cgroup file: the first "0::"
// line's path, or "" when there is none or it is unusable. A ".." component is refused rather than
// left for path.Join to clean away: cgroup_namespaces(7) documents that the pathname "will show
// ../ entries for each ancestor level" when the named cgroup lies outside the reading namespace's
// root, and joining such a path onto the mount point would name a directory outside the cgroup2
// mount altogether. Pure over its input.
func ownCgroup(procCgroup []byte) string {
	p, ok := unifiedPath(procCgroup)
	if !ok || !strings.HasPrefix(p, "/") || strings.Contains(p, "\x00") {
		return ""
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return ""
		}
	}
	return p
}

// delegatedSubtreeIn returns the absolute path, under mount, of the user@<uid>.service ancestor of this
// process's cgroup v2 path, or "" when the process is not inside one. Pure over its input; the mount is
// explicit so the namespace-agreement check and its tests can run against a temporary directory, and
// Detect uses delegatedCandidate, which also checks that the mount agrees with the path.
func delegatedSubtreeIn(mount string, procCgroup []byte, uid int) string {
	p := ownCgroup(procCgroup)
	if p == "" {
		return ""
	}
	unit := fmt.Sprintf("user@%d.service", uid)
	// The ancestor is rebuilt from the segments that matched rather than by cutting p at the first
	// "/user@<uid>.service" substring: a substring search also matches an earlier segment that only
	// starts with the unit name, and the path before it names a sibling, not an ancestor.
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if seg == unit {
			return path.Join(mount, strings.Join(segs[:i+1], "/"))
		}
	}
	return ""
}

// canonicalSubtree is the systemd user delegation root for uid under the real mount.
func canonicalSubtree(uid int) string {
	return canonicalSubtreeIn(Mount, uid)
}

// UserSubtree is the canonical subtree systemd delegates to uid's user manager,
// /sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service, where an unprivileged launcher of that uid
// makes its runs' scopes. A root sweep of that user's run looks for its scope there (internal/runtime).
func UserSubtree(uid int) string { return canonicalSubtree(uid) }

// canonicalSubtreeIn is canonicalSubtree against an explicit mount point, so that every candidate
// candidatesIn lists comes out of the mount whose agreement it has just judged; a candidate that
// ignored the parameter would sit outside that judgement.
func canonicalSubtreeIn(mount string, uid int) string {
	return fmt.Sprintf("%s/user.slice/user-%d.slice/user@%d.service", mount, uid, uid)
}

// writable reports whether root is a cgroup2fs directory whose cgroup.procs this process may write.
func writable(root string) error {
	if err := checkCgroup2(root); err != nil {
		return err
	}
	if err := unix.Access(path.Join(root, fileProcs), unix.W_OK); err != nil {
		return fmt.Errorf("access(%s/%s, W_OK): %w", root, fileProcs, err)
	}
	return nil
}

// checkCgroup2 verifies the statfs magic of root (D3's first half).
func checkCgroup2(root string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return fmt.Errorf("statfs(%s): %w", root, err)
	}
	if uint64(st.Type) != unix.CGROUP2_SUPER_MAGIC { //nolint:unconvert // Type is int64 on some arches
		return fmt.Errorf("%w: %s has magic %#x", ErrNotCgroup2, root, st.Type)
	}
	return nil
}
