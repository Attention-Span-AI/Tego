// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// As is who asked and from where: the object's "as". The dashboard, which describes no shell, leaves it nil.
type As struct {
	// User and UID are the invoking user (config.InvokingUID): under sudo, the user who ran sudo.
	User string `json:"user"`
	UID  int    `json:"uid"`
	// Root is a root process in the initial user namespace.
	Root bool `json:"root"`
	// SSH is a process with SSH_CONNECTION or SSH_CLIENT set: a login over SSH starts outside the user manager.
	SSH bool `json:"ssh"`
	// InUserCgroup is a process inside user@<uid>.service's cgroup tree, where tier 1 places its runs.
	InUserCgroup bool `json:"in_user_cgroup"`
	// InRun is a process inside a tego run's cgroup, or one that cannot be shown to be outside every run.
	InRun bool `json:"in_run"`
	// Where is the place a check made from here is stored under (Check.Where).
	Where string `json:"where"`
	// Scope is the command that opens a shell in the user manager's cgroup from here (OpenScope), and ScopeMissing
	// why there is none, for a process outside that cgroup that is not root; both "" otherwise.
	Scope        string `json:"scope,omitempty"`
	ScopeMissing string `json:"scope_missing,omitempty"`
	// ScopeAs is the user Scope opens a shell as when the person who reads it is another user (Opening.As): this
	// process was started from another user's shell through sudo or su, so Scope begins with sudo -u. "" otherwise.
	ScopeAs string `json:"scope_as,omitempty"`
}

// Host is the machine: its kernel release and this boot's id.
type Host struct {
	Kernel string `json:"kernel"`
	BootID string `json:"boot_id"`
}

// Invoker describes this process (As). A part it cannot read is the cautious answer: a cgroup it cannot read is not
// the user manager's, and a run membership it cannot rule out is in a run.
func Invoker() As {
	uid, _ := config.InvokingUID()
	a := As{UID: uid, Root: config.InitNSRoot(), SSH: os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != ""}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		a.User = u.Username
	}
	cg, _ := os.ReadFile("/proc/self/cgroup")
	a.InUserCgroup = inUserManager(cg, uid)
	in, err := runscope.InRun()
	a.InRun = in || err != nil
	a.Where = place(a.Root, a.InUserCgroup)
	if a.Where == WhereShell {
		o := OpenScope()
		a.Scope, a.ScopeMissing, a.ScopeAs = o.Command, o.Missing, o.As
	}
	return a
}

// DefaultScope is the command that opens a shell in the user manager's cgroup, as the docs and the fix line write it.
const DefaultScope = "systemd-run --user --scope bash"

// Opening is how a shell in the invoking user's user manager's cgroup is opened from here (OpenScope).
type Opening struct {
	// Command opens it; "" when none is known to work from here, and Missing says why.
	Command, Missing string
	// As is the user Command opens the shell as, its name from the passwd entry as Command writes it, when the person
	// who reads the line is another user (config.StartedByAnother): Command then begins with sudo -u. "" when the reader is
	// the user this process runs as.
	As string
}

// OpenScope is the command that opens a shell in the invoking user's user manager's cgroup from this process, where
// tier 1 starts its runs (DefaultScope, with $SHELL's name in place of bash when it is one of scopeShells and on PATH),
// or "" and why none is known to work from here: systemd-run is not on PATH, or the user manager cannot be reached
// from this shell (systemd-run --user connects through $XDG_RUNTIME_DIR, which su and sudo -u leave unset or another
// user's). There, when the user's own logind folder (/run/user/<uid>, a directory the user owns) holds its manager's
// socket, as after loginctl enable-linger, the command names that folder: XDG_RUNTIME_DIR=/run/user/<uid> before
// systemd-run (the review's S5: after linger, sudo -u svc tego setup named no command). When this process was started
// from another user's shell through sudo or su (config.StartedByAnother), the person who reads the line types it in that
// shell, so the command is that one with sudo -u and this user's name in front: typed without it, it opened the
// reader's own scope on Ubuntu 24.04 and AlmaLinux 9.8, where tego setup then said ready for the wrong user, and failed
// on Fedora 44 (acceptance 3, 2026-11-11). Its shell is then bash, whatever $SHELL says: the shell was this process's,
// and the fix: line beside it (cgroup.PlacementFix, cgroup.NoManagerFix) names bash, so both name one command. It starts no program; it looks at PATH, a folder, its sockets and /proc. A
// process whose real and effective uids differ gets no command. The next: lines of tego setup, doctor, run, watch,
// test and learn name it where they would otherwise name a command that fails from here (acceptance B, 2026-11-11); tego agents, which runs as root, names DefaultScope.
func OpenScope() Opening {
	uid := os.Getuid()
	if uid != os.Geteuid() {
		return Opening{Missing: "this process's real and effective uids differ, so whose user manager to open a shell in is not known"}
	}
	var r reader
	if config.StartedByAnother("/proc", os.Getpid(), uid) {
		r.other = true
		if u, err := config.LookupPasswd(uid); err == nil {
			r.name, r.named = u.Username, true
		}
	}
	return openScope(os.Getenv, uid, config.LogindRuntimeRoot, r)
}

// reader is who reads OpenScope's command: the user this process runs as (the zero reader), or another user, who
// started it through sudo or su (other), with this user's name from the passwd entry (named when there is one).
type reader struct {
	other bool
	name  string
	named bool
}

// openScope is OpenScope over getenv, uid, logindRoot (config.LogindRuntimeRoot) and its reader, for tests.
func openScope(getenv func(string) string, uid int, logindRoot string, r reader) Opening {
	path := getenv("PATH")
	if !onPath(path, "systemd-run") {
		return Opening{Missing: "systemd-run is not on your PATH"}
	}
	own := filepath.Join(logindRoot, strconv.Itoa(uid))
	prefix := ""
	if r.other {
		// Typed in the other user's shell, whose XDG_RUNTIME_DIR is their own: the user's logind folder, always.
		if !ownDir(own, uid) || managerUnder(own, uid) != "" {
			return Opening{Missing: "the user manager of uid " + strconv.Itoa(uid) + " keeps no socket under " + own +
				", so systemd-run --user cannot reach it from another user's shell"}
		}
	} else if missing := managerUnder(getenv("XDG_RUNTIME_DIR"), uid); missing != "" {
		if !ownDir(own, uid) || managerUnder(own, uid) != "" {
			return Opening{Missing: missing}
		}
		prefix = "XDG_RUNTIME_DIR=" + own + " " // a constant folder and a number: nothing from the environment
	}
	shell := "bash"
	if b := filepath.Base(getenv("SHELL")); !r.other && getenv("SHELL") != "" && slices.Contains(scopeShells, b) && onPath(path, b) {
		shell = b
	}
	if !onPath(path, shell) {
		return Opening{Missing: "bash is not on your PATH"}
	}
	if !r.other {
		return Opening{Command: prefix + "systemd-run --user --scope " + shell}
	}
	// cgroup.ScopeAsCommand's words (this package links no engine package): the name from the passwd entry as one
	// quoted word, or '#<uid>' when there is none or sudo would not read it as the name (config.PlainUserName).
	word := "'#" + strconv.Itoa(uid) + "'"
	if r.named && config.PlainUserName(r.name) {
		word = shellword.Quote(r.name)
	}
	return Opening{Command: "sudo -u " + word + " XDG_RUNTIME_DIR=" + own + " systemd-run --user --scope " + shell, As: word}
}

// managerUnder is "" when rt, an absolute folder, holds a socket of uid's user manager (systemd/private or bus), which
// systemd-run --user connects through; else why not.
func managerUnder(rt string, uid int) string {
	if rt == "" || !filepath.IsAbs(rt) {
		return "XDG_RUNTIME_DIR is not set in this shell (as after su or sudo -u), so systemd-run --user cannot reach your user manager"
	}
	if !ownSocket(filepath.Join(rt, "systemd", "private"), uid) && !ownSocket(filepath.Join(rt, "bus"), uid) {
		return "your user manager's socket is not under " + record.Printable(rt) + ", so systemd-run --user cannot reach it"
	}
	return ""
}

// ownDir reports whether path is a directory, not a link, that uid owns.
func ownDir(path string, uid int) bool {
	var st unix.Stat_t
	return unix.Lstat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && int(st.Uid) == uid
}

// scopeShells are the login shells OpenScope names in place of bash: a fixed list, so the environment chooses among
// these words and never supplies one (ADR 0142 (4)). $SHELL was taken by its characters alone, and a nologin or false
// login shell, or any program by the name of $SHELL's base on PATH, became the command (the review's S1).
var scopeShells = []string{"bash", "zsh", "fish", "sh", "dash", "ksh", "mksh", "tcsh", "csh"}

// onPath reports whether name is an executable file in one of path's absolute folders.
func onPath(path, name string) bool {
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			continue
		}
		var st unix.Stat_t
		p := filepath.Join(dir, name)
		if unix.Stat(p, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && unix.Access(p, unix.X_OK) == nil {
			return true
		}
	}
	return false
}

// ownSocket reports whether path is a socket uid owns.
func ownSocket(path string, uid int) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK && int(st.Uid) == uid
}

// place is the Where of a check made by a process that is root or not, in the user manager's cgroup or not.
func place(root, inUserCgroup bool) string {
	switch {
	case root:
		return WhereRoot
	case inUserCgroup:
		return WhereUserManager
	}
	return WhereShell
}

// InUserManager is inUserManager: whether procCgroup, a /proc/<pid>/cgroup, places that process at or beneath
// user@<uid>.service's cgroup.
func InUserManager(procCgroup []byte, uid int) bool { return inUserManager(procCgroup, uid) }

// inUserManager reports whether /proc/self/cgroup's unified line (0::<path>) names a cgroup at or beneath
// user@<uid>.service, the user manager's tree.
func inUserManager(procCgroup []byte, uid int) bool {
	svc := fmt.Sprintf("/user@%d.service", uid)
	for _, line := range strings.Split(string(procCgroup), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		i := strings.Index(path, svc)
		return i >= 0 && (len(path) == i+len(svc) || path[i+len(svc)] == '/')
	}
	return false
}

// ThisHost is this machine's kernel release and boot id; a part it cannot read is "".
func ThisHost() Host {
	var h Host
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.Kernel = unix.ByteSliceToString(u.Release[:])
	}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		h.BootID = strings.TrimSpace(string(b))
	}
	return h
}

// BuildID is the build a check is stored for: the version and commit the binary reports, and the running executable's
// device, inode, size and modification time, so a rebuilt or reinstalled tego is another build even when its version
// says the same (the rule the run-probe cache keys on, internal/doctor). It is "" when the executable cannot be
// stat'ed: no stored check is then used, and none is stored.
func BuildID(version, commit string) string { return BuildIDOf("/proc/self/exe", version, commit) }

// BuildIDOf is BuildID of the tego binary at exe, followed through links as /proc/self/exe is: the dashboard, which
// runs as tego-control from a sealed copy, names the build of the tego a person types (ADR 0142, the dashboard's
// guide), with the version and commit of its own release, which a matched tego pins. "" when exe cannot be stat'ed.
func BuildIDOf(exe, version, commit string) string {
	var st unix.Stat_t
	if err := unix.Stat(exe, &st); err != nil {
		return ""
	}
	return fmt.Sprintf("tego=%s commit=%s exe=%d:%d:%d:%d.%09d", version, commit, st.Dev, st.Ino, st.Size,
		st.Mtim.Sec, st.Mtim.Nsec)
}
