// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An alternate (ADR 0057, SEMANTICS §6) is a third answer to a held file open: a person names a file, and this loop
// delivers that file's descriptor in place of the target as the open's result, by the same atomic ADDFD+SEND an
// approved open uses. Only a person supplies it, and it is still treated as an attack surface: a mistyped path, or
// one the agent talked the person into, must never reach tego's own state, a path the contract protects, or anything
// the agent's own credentials could not open; and this loop, which runs outside the agent's Landlock domain with the
// person's full identity at tier 1, must never be the one that resolves the person's path, since the agent can steer
// a path between the person's command and an open here (a directory it renames, a symbolic link it swaps in): a
// confused deputy that would hand the agent a file outside its domain, even one to write. So:
//   - the file's identity is fixed when the person names it: `tego alternate` opens the path in the person's own
//     process, O_PATH, with no symbolic link and no magic link anywhere on the way (openat2
//     RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS), and passes that descriptor over the broker's socket
//     (ask.AlternateFile); this loop never looks the path up;
//   - every check is made on that descriptor: a regular file, with one link (a hard link made into a protected tree
//     has a second name elsewhere), on no kernel pseudo filesystem (procfs's /proc/<pid>/mem and environ, sysfs,
//     cgroupfs, bpffs, ...), and the path the kernel names the descriptor by (/proc/self/fd/<n>) names the same inode
//     in this process's view (sameInodeHere) and lies outside tego's own state (the table's and Options.OwnState),
//     the contract file's directory (but beneath a write entry), every deny_read, fs.ask_read and implicit entry and
//     every declared deny_read glob and built-in deny_read path, has no name of the built-in .env list, and for a
//     write is of no built-in deny_write class by name, lies outside every deny_write target and beneath a write
//     entry or an fs.ask scope (alternateRefusal), no live block or unlifted read fence entry refuses the agent's own
//     open of it (alternateLiveRefusal), and the contract's gate, scoring the agent's own open of it, does not refuse
//     it (alternateGate);
//   - only then is the file reopened through the descriptor, with no lookup (/proc/self/fd/<n>), as the agent (the
//     held task's uid, gids, groups and umask: runAskOpenAs), so what the person names can never grant more than the
//     agent's credentials could open, with the agent's flags (alternateFlags): read-only for a held read; for a held
//     write the agent's access mode, append, truncate and sync flags, create and exclusive dropped (the alternate
//     exists, and the person's choice replaces the create). The reopened descriptor must be the inode checked.
// The check at answer time (Request.Alternates) runs the same steps and reopens with the access mode alone, so it has
// no side effect; the delivery runs them all again on the same descriptor, since the file can be renamed or linked
// between the answer and the delivery. A standing alternate keeps the person's descriptor and repeats them per
// delivery.

// askAlternateKernel checks and reopens an alternate and delivers a descriptor in place of a held open's
// (sysKernel). A kernel without it takes no alternate: the request carries no check, and the broker answers
// ErrNoAlternate.
type askAlternateKernel interface {
	// OpenAlternate checks alt as h's task would (see above), refuse naming what may not be delivered; it returns
	// alt reopened with flags (closed again, -1, when probe, which reopens with the access mode alone), and the path
	// the kernel names it by in this process's view.
	OpenAlternate(h *heldAskOpen, alt *ask.AlternateFile, flags int, probe bool, refuse func(resolved string) string) (int, string, error)
	// DeliverFD completes the held notification id with a duplicate of fd as the open's result (ADDFD|SEND); the
	// caller keeps fd.
	DeliverFD(id uint64, fd int, flags int) (int, error)
}

// errAlternate is an alternate this loop refuses; its text says why, and reaches the person.
type errAlternate struct{ why string }

func (e *errAlternate) Error() string { return e.why }

func alternateRefused(format string, args ...any) error {
	return &errAlternate{why: fmt.Sprintf(format, args...)}
}

// pseudoFS are the kernel filesystems whose regular files are kernel interfaces, not stored data: a file on one is
// never an alternate (procfs's /proc/<pid>/mem, environ and fd tables, sysfs and cgroupfs controls, bpffs pins,
// securityfs and the like). Several have no constant in x/sys and are spelled as linux/magic.h does.
var pseudoFS = map[int64]string{
	unix.PROC_SUPER_MAGIC: "procfs", unix.SYSFS_MAGIC: "sysfs", unix.CGROUP_SUPER_MAGIC: "cgroupfs",
	unix.CGROUP2_SUPER_MAGIC: "cgroup2", unix.BPF_FS_MAGIC: "bpffs", unix.DEBUGFS_MAGIC: "debugfs",
	unix.TRACEFS_MAGIC: "tracefs", unix.SECURITYFS_MAGIC: "securityfs", unix.SELINUX_MAGIC: "selinuxfs",
	unix.SMACK_MAGIC: "smackfs", unix.EFIVARFS_MAGIC: "efivarfs", unix.PSTOREFS_MAGIC: "pstore",
	unix.BINFMTFS_MAGIC: "binfmt_misc", unix.DEVPTS_SUPER_MAGIC: "devpts", unix.RDTGROUP_SUPER_MAGIC: "resctrl",
	unix.NSFS_MAGIC: "nsfs", unix.PID_FS_MAGIC: "pidfs", unix.ANON_INODE_FS_MAGIC: "anon_inodefs",
	unix.SOCKFS_MAGIC: "sockfs", unix.PIPEFS_MAGIC: "pipefs", unix.SECRETMEM_MAGIC: "secretmem",
	unix.DMA_BUF_MAGIC: "dmabuf", unix.BDEVFS_MAGIC: "bdev", unix.USBDEVICE_SUPER_MAGIC: "usbdevfs",
	unix.BINDERFS_SUPER_MAGIC: "binderfs", unix.DEVMEM_MAGIC: "devmem", unix.AAFS_MAGIC: "apparmorfs",
	0x62656570: "configfs", 0x65735543: "fusectl", 0x19800202: "mqueue",
}

// alternateFlags is what an alternate for a held open of flags is reopened with: for a held read, read-only, and an
// open with any write flag is no read (refused); for a held write, the agent's flags less O_CREAT, O_EXCL (the
// alternate exists, and the person's choice replaces the create), O_NOFOLLOW (the final component was pinned
// unfollowed already), O_DIRECTORY, O_TMPFILE and O_PATH. probe keeps the access mode alone, which has no side
// effect, for the check at answer time. O_CLOEXEC and O_NONBLOCK are this process's own on the reopen; the
// delivered descriptor gets the agent's.
func alternateFlags(flags int, read, probe bool) (int, error) {
	if read && (decide.IsWriteOpen(flags) || flags&unix.O_ACCMODE != unix.O_RDONLY) {
		return 0, alternateRefused("a held read takes a read-only alternate, and this open asked to write")
	}
	if !read && !decide.IsWriteOpen(flags) {
		return 0, alternateRefused("a held write takes an alternate opened to write, and this open asked for no write")
	}
	out := flags &^ (unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_TMPFILE | unix.O_PATH)
	if probe {
		out = flags & unix.O_ACCMODE
	}
	return out | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY, nil
}

// OpenAlternate is askAlternateKernel's, on the real filesystem (see the file's first comment).
func (k sysKernel) OpenAlternate(h *heldAskOpen, alt *ask.AlternateFile, flags int, probe bool, refuse func(string) string) (int, string, error) {
	read := !decide.IsWriteOpen(flags)
	reopen, err := alternateFlags(flags, read, probe)
	if err != nil {
		return -1, "", err
	}
	if alt == nil {
		return -1, "", alternateRefused("no file was named")
	}
	fd, resolved := -1, ""
	err = runAskOpenAs(h.creds, h.umask, func() error {
		return alt.Control(func(pin int) error {
			var e error
			fd, resolved, e = openAlternate(pin, alt.Named, reopen, refuse)
			return e
		})
	})
	if err != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if errors.Is(err, os.ErrClosed) {
			err = alternateRefused("the descriptor of %s is closed", alt.Named)
		}
		return -1, "", err
	}
	if probe {
		_ = unix.Close(fd)
		return -1, resolved, nil
	}
	return fd, resolved, nil
}

// A person's choice cannot override deny_read (ADR 0057 D2). Consult the
// retained identities even for a write-only alternate, before any truncation.
func (l *Loop) heldAlternateCheck(c *compiled, a *ask.AlternateFile) error {
	if c.heldReads == nil {
		return nil
	}
	return a.Control(func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if rule, refused := l.heldReadIdentityRefusal(c, unix.O_RDONLY, decide.HeldReadID{Dev: st.Dev, Ino: st.Ino}, true); refused {
			return alternateRefused("%s", rule)
		}
		return nil
	})
}

// openAlternate is the checks on pin, the descriptor of the file the person named (by named), and its reopen, on
// the thread runAskOpenAs gave the task's credentials.
func openAlternate(pin int, named string, reopen int, refuse func(string) string) (int, string, error) {
	var st unix.Stat_t
	if err := unix.Fstat(pin, &st); err != nil {
		return -1, "", err
	}
	switch {
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		return -1, "", alternateRefused("%s is a symbolic link; name the file it points to", named)
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return -1, "", alternateRefused("%s is not a regular file", named)
	case st.Nlink != 1:
		return -1, "", alternateRefused("%s has %d links; an alternate has one name only", named, st.Nlink)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(pin, &fs); err != nil {
		return -1, "", err
	}
	if name, ok := pseudoFS[int64(fs.Type)]; ok {
		return -1, "", alternateRefused("%s lies on %s, a kernel interface, not a stored file", named, name)
	}
	resolved, err := readlinkRaw("/proc/self/fd/" + strconv.Itoa(pin))
	if err != nil {
		return -1, "", err
	}
	if !strings.HasPrefix(resolved, "/") || !sameInodeHere(resolved, &st) {
		return -1, "", alternateRefused("%s is not a file this process sees by a path (it was removed, renamed while checked, or lies outside this process's view)", named)
	}
	if why := refuse(resolved); why != "" {
		return -1, "", alternateRefused("%s", why)
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pin), reopen, 0)
	if err != nil {
		return -1, "", alternateRefused("%s cannot be opened by the agent as the held open asked: %v", named, err)
	}
	var got unix.Stat_t
	if err = unix.Fstat(fd, &got); err != nil || got.Dev != st.Dev || got.Ino != st.Ino || got.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		if err == nil {
			err = alternateRefused("%s changed while it was opened", named)
		}
		return -1, "", err
	}
	return fd, resolved, nil
}

// DeliverFD is askAlternateKernel's: Linux's ADDFD+SEND returns the injected descriptor and completes the original
// syscall atomically, as an approved open's delivery does (CompleteAskOpen). The descriptor goes with the agent's
// O_NONBLOCK and O_CLOEXEC.
func (k sysKernel) DeliverFD(id uint64, fd int, flags int) (int, error) {
	if err := setNonblock(fd, flags&unix.O_NONBLOCK != 0); err != nil {
		return -1, err
	}
	return k.addFDSend(id, fd, flags)
}

// alternateRefusal says why the file an alternate opened, which the kernel names resolved, may not be delivered for
// a held open (a write when write), or "" when it may (ADR 0057 D2). Refused, for any held open, a file:
//   - at or beneath tego's own state (RuleTable.OwnState, and own, what the launcher adds: $XDG_RUNTIME_DIR/tego);
//   - whose name is one of the built-in .env list's (a typo of .env.example must not hand over the secret, whether
//     or not that .env existed when the table compiled);
//   - inside the contract file's directory, unless it lies beneath a write entry: R10 keeps the contract file out
//     of every write entry, and a file beneath one holds bytes the agent could write already, the common stand-in;
//   - at or beneath a deny_read or fs.ask_read entry (the built-in ones included) or an implicit entry (the run
//     directory's ledger root, /sys/fs/cgroup, /sys/fs/bpf), or a declared deny_read glob or a built-in deny_read
//     path names it or a directory above it, whether or not it existed when the table compiled
//     (RuleTable.DenyReadPatterns).
//
// And for a write, a file:
//   - at or beneath tego's own state a run may read (RuleTable.OwnReadable: the user registry's agents/ and skills/);
//   - of a built-in deny_write class by its names alone, wherever it lies (agent.WriteAlternateClass: git hooks
//     and config, harness and editor settings, shell startup files, per-user git config);
//   - that is a deny_write target or lies beneath one (the built-in set, and the one the fs.ask scopes carry);
//   - outside every write entry and fs.ask scope: what the contract lets the agent write, or be asked to write,
//     is all a write alternate may be. Anywhere else the supervisor, outside the agent's Landlock domain, would
//     give the agent a writable descriptor of a file its own domain never reaches (a crontab, an autostart entry,
//     ~/.ssh/authorized_keys), which no list of names can enumerate.
//
// Each entry is asked under both of its spellings. The "/" an `fs: {}` table marks every write refused with is a
// write guard, not a protected tree, and is skipped.
func alternateRefusal(rt *agent.RuleTable, own []string, resolved string, write bool) string {
	p := filepath.Clean(resolved)
	for _, o := range append(slices.Clip(rt.OwnState), own...) {
		if agent.Covers(o, p) {
			return p + " lies inside tego's own state " + o
		}
	}
	if agent.IsBuiltInEnvName(filepath.Base(p)) {
		return p + " is named as the built-in .env list's secrets are; an alternate is never one"
	}
	// A declared name entry covers it where the run's mechanisms decide names (ADR 0043 interface 2: the alternate is
	// opened outside any plane).
	if rt.Tier == backend.TierCgroup || rt.Tier == backend.TierBPFLSM {
		if n := decide.NewNameIndex(rt); n != nil {
			if m, ok := n.Match(p, false); ok {
				return p + " is covered by the name entry " + n.Rule(m, -1)
			}
		}
	}
	underWrite := coveredByKind(rt.FS, agent.FSWrite, p)
	if rt.ContractPath != "" && !underWrite {
		for _, c := range contractSpellings(rt) {
			if dir := filepath.Dir(c); agent.Covers(dir, p) {
				return p + " lies inside the contract file's directory " + dir + ", beneath no write entry"
			}
		}
	}
	// The nearest protected entry is named: the one the person most likely meant to avoid.
	var nearest *agent.FSRule
	depth := -1
	for i := range rt.FS {
		r := &rt.FS[i]
		if r.Kind != agent.FSDenyRead && r.Kind != agent.FSImplicit {
			continue
		}
		for _, sp := range r.Spellings() {
			if sp == "" || (r.Kind == agent.FSImplicit && filepath.Clean(sp) == "/") {
				continue
			}
			if agent.Covers(sp, p) && len(sp) > depth {
				nearest, depth = r, len(sp)
			}
		}
	}
	if nearest != nil {
		return p + " lies inside " + nearest.RuleName() + ", which the contract protects"
	}
	if d, ok := rt.DenyReadPatternOf(p); ok {
		return p + " is named by " + d.Rule + ", which the contract protects, though it was not there when the contract compiled"
	}
	if !write {
		return ""
	}
	for _, o := range rt.OwnReadable {
		if agent.Covers(o, p) {
			return p + " lies inside tego's own state " + o + ", which a run may read but never write"
		}
	}
	if what, ok := agent.WriteAlternateClass(p); ok {
		return p + " is " + what + ", which runs code outside the run; no write alternate is one, wherever it lies"
	}
	if t, denied := rt.DenyWriteTarget(p, false); denied {
		return p + " is " + t.RuleName() + ", which no write reaches"
	}
	if t, denied := rt.AskDenyWriteTarget(p, false); denied {
		return p + " is " + t.RuleName() + ", which no write reaches"
	}
	if !underWrite && !coveredByKind(rt.FSAsk, agent.FSAsk, p) {
		return p + " lies outside every write entry and fs.ask scope; a write alternate is a file the contract lets the agent write or be asked to write"
	}
	return ""
}

// alternateGate is the contract's gate on the file an alternate opened, which the kernel names resolved, for a held
// open with flags, as the agent's own open of it would be scored (scoreOpen: an O_RDWR write by the read predicates
// too): the decision, nil when the gate scores no such open, and why it
// refuses the file, "" when it does not. A refusal is the contract protecting the file exactly as a deny_read entry
// does, and no person's answer lifts it, for the target or for the file in its place. Its floor is ask, since the open
// reaches the agent through a person's answer, so a score at or below the refusal threshold leaves the person's choice
// standing and is what the delivered line records.
func alternateGate(rt *agent.RuleTable, resolved string, flags int) (*gate.Decision, string) {
	if !openGated(rt.Gate, flags) {
		return nil, ""
	}
	g := scoreOpen(rt.Gate, gate.Ask, filepath.Clean(resolved), flags, rt.Workdir)
	if g.Verdict == gate.Refused {
		return &g, fmt.Sprintf("%s is refused by the contract's gate (%s, score %d), which no answer lifts", filepath.Clean(resolved), g.Rule, g.Score)
	}
	return &g, ""
}

// alternateLiveRefusal says why the run's live Set refuses the file an alternate opened, which the kernel names
// resolved, for a held open with flags, or "" when it does not: a live read or path block, or an Adjustable run's read
// fence entry not lifted, that would refuse the agent's own open of the file with those flags (liveFS's access class,
// liveAccess). The compiled table cannot say it: a live block is not in it, and compile took a read fence entry's
// deny_read out of it (ADR 0125 decision 2), so alternateRefusal alone would hand over a file the live layer refuses
// (the person's alternate inside an unlifted read entry).
func alternateLiveRefusal(s *liveblock.Set, resolved string, flags int) string {
	p := filepath.Clean(resolved)
	e, ok := s.MatchPath(p, liveAccess(record.FSOpen, flags, false))
	if !ok {
		return ""
	}
	if e.Fence {
		return p + " lies inside " + e.Rule() + ", which the run refuses until that fence entry is lifted"
	}
	return p + " lies inside " + e.Rule() + ", which a person blocked while the run runs"
}

// alternateCheck is the refusal an alternate's open for a held open with flags is put to (OpenAlternate's refuse): the
// protected paths (alternateRefusal), then the live Set (alternateLiveRefusal) and then the gate (alternateGate). The
// live Set is loaded each time the check runs, from live (compiled.blocks), never when the check is built: at the
// answer, which may come long after the request, and again at the delivery, so a block or a restore made in between
// holds. When decided is not nil, the gate's decision on the file is kept there for the delivered open's line; the
// check at answer time, which may run on another goroutine while a late answer races the hold, passes nil.
func alternateCheck(rt *agent.RuleTable, own []string, live func() *liveblock.Set, flags int, decided **gate.Decision) func(string) string {
	write := isWriteOpen(flags)
	return func(resolved string) string {
		if why := alternateRefusal(rt, own, resolved, write); why != "" {
			return why
		}
		if live != nil {
			if why := alternateLiveRefusal(live(), resolved, flags); why != "" {
				return why
			}
		}
		g, why := alternateGate(rt, resolved, flags)
		if decided != nil {
			*decided = g
		}
		return why
	}
}

// coveredByKind reports whether an entry of rules of kind lies at or above p, under either of its spellings.
func coveredByKind(rules []agent.FSRule, kind agent.FSKind, p string) bool {
	for i := range rules {
		if rules[i].Kind != kind {
			continue
		}
		for _, sp := range rules[i].Spellings() {
			if sp != "" && agent.Covers(sp, p) {
				return true
			}
		}
	}
	return false
}

// contractSpellings is the contract file's path as declared and as compile resolved it (its implicit entry).
func contractSpellings(rt *agent.RuleTable) []string {
	out := []string{rt.ContractPath}
	for i := range rt.FS {
		if r := &rt.FS[i]; r.Kind == agent.FSImplicit && r.Path == rt.ContractPath && r.Resolved != "" && r.Resolved != r.Path {
			out = append(out, r.Resolved)
		}
	}
	return out
}
