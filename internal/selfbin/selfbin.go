// SPDX-License-Identifier: Apache-2.0

package selfbin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The reasons Named gives for a binary it will not name.
const (
	// NoPath: the path cannot be read, or no longer identifies the running file (it was replaced or removed).
	NoPath = "this tego's path cannot be named, so no sudo line is given."
	// Unsafe: the path holds a character that does not print safely.
	Unsafe = "this tego's path cannot be shown safely, so no sudo line is given."
	// Untrusted: path ownership or write authority cannot be verified.
	Untrusted = "cannot verify that only root or you can change this tego's path, so no command is shown; install Tego in a folder only root or you can write."
	// NoExec: the process, which runs as the account the line is for, cannot execute the file.
	NoExec = "the account cannot run this copy of tego; install it where it can."
)

// procSelfExe names the running file by identity: the kernel's link opens the file this process runs, whatever its
// name became.
const procSelfExe = "/proc/self/exe"

// Safe reports whether s may be written into a line a person reads and pastes. The rule, decided once: s is valid
// UTF-8 and record.Printable leaves it as it is, so it holds no C0 or C1 control (a newline or an escape could forge a
// second command or move the cursor), no DEL, no format character (a bidirectional override reorders what is shown), no
// line or paragraph separator and no tag character. Shell quoting keeps a line's syntax intact; it does not keep what
// the terminal shows honest, so a value that fails this is not quoted but declined.
func Safe(s string) bool { return utf8.ValidString(s) && record.Printable(s) == s }

// Named is the running binary as a sudo line writes it: its absolute path, links followed, as one quoted word
// (shellword.Quote), from executable (os.Executable in the products) and never from PATH. why is "" when the word may
// be used; otherwise word is "" and why is NoPath, Unsafe, NoExec, Untrusted, or a named group-membership repair.
// The file must be a regular file whose
// device and inode are those of /proc/self/exe, so a binary that was unlinked and replaced (by another file, or a
// directory) at the same path is refused, and this process, which runs as the account a sudo line is for, must be able
// to execute it. The file and every resolved ancestor must also pass the owner and
// write-permission check. It reads the system each call; a caller that wants it once wraps it.
func Named(executable func() (string, error)) (word, why string) {
	return namedPath(executable, procSelfExe, os.Lstat)
}

func namedPath(executable func() (string, error), self string, stat func(string) (os.FileInfo, error)) (word, why string) {
	var detail string
	word, why = namedPathWithTrust(executable, self, stat, func(path string, uid int, stat func(string) (os.FileInfo, error)) bool {
		detail = chainRefusal(path, uid, stat, func() groupTrust { return systemGroupTrust(uid) }, noAccessACL)
		return detail == ""
	})
	if why == Untrusted && detail != "" {
		return "", detail
	}
	return word, why
}

func namedPathWithTrust(executable func() (string, error), self string, stat func(string) (os.FileInfo, error), trust func(string, int, func(string) (os.FileInfo, error)) bool) (word, why string) {
	path, why := checkedPath(executable, self)
	if why != "" {
		return "", why
	}
	if !trust(path, os.Geteuid(), stat) {
		return "", Untrusted
	}
	return shellword.Quote(path), ""
}

// noAccessACL queries size only. Named ACL grants are masked into the group bits
// but need not belong to the directory's group. Never treat them as private.
func noAccessACL(path string) bool {
	_, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	return err == unix.ENODATA || err == unix.EOPNOTSUPP
}

// groupRefusal is one folder of the chain whose group can write it and whose membership could not be established.
type groupRefusal struct {
	folder, group, why string
	gid                uint32
}

// chainRefusal walks path's chain. membership is asked for the account evidence only when a folder of the chain is
// writable by its group, and once: a path with no such folder reads no account file and waits for none. The walk goes
// to the root even after a folder whose membership cannot be established, so that one message names every such folder
// and one chmod cures them all (groupRepair); any other refusal ends the walk with Untrusted, since chmod g-w on the
// named folders would not cure it.
func chainRefusal(path string, uid int, stat func(string) (os.FileInfo, error), membership func() groupTrust, aclSafe func(string) bool) string {
	file := true
	var groups groupTrust
	loaded := false
	var open []groupRefusal
	for {
		info, err := stat(path)
		if err != nil {
			return Untrusted
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 && owner.Uid != uint32(uid) {
			return Untrusted
		}
		if file && !info.Mode().IsRegular() || !file && !info.IsDir() {
			return Untrusted
		}
		// A sticky directory such as /tmp allows creation, but only its owner,
		// root, or the child's owner may rename that child. Every child and parent
		// in this chain has a trusted owner. Sticky never protects file contents.
		if file {
			if info.Mode().Perm()&0o022 != 0 {
				return Untrusted
			}
		} else if info.Mode()&os.ModeSticky == 0 {
			if info.Mode().Perm()&0o002 != 0 {
				return Untrusted
			}
			if info.Mode().Perm()&0o020 != 0 {
				if !loaded {
					groups, loaded = membership(), true
				}
				if use, exists := groups.groups[owner.Gid]; !groups.complete || !exists || use.password != "" {
					group := use.name
					if group == "" {
						group = "unknown"
					}
					why := groups.incomplete
					if why == "" && exists && use.password != "" {
						// A password admits accounts no file lists (newgrp), so the listed members are not all of them.
						why = "the group can be joined with a password (set in " + use.password + ")"
					}
					if why == "" {
						why = "complete membership evidence is unavailable"
					}
					open = append(open, groupRefusal{folder: path, group: group, gid: owner.Gid, why: why})
				} else if !groups.allows(owner.Gid) || !aclSafe(path) {
					return Untrusted
				}
			}
		}
		parent := filepath.Dir(path)
		if parent == path {
			return groupRepair(open)
		}
		path, file = parent, false
	}
}

// groupRepair is the one message for every folder of the chain whose membership could not be established: what is
// missing, that no command is shown, and one chmod g-w for all of them, outermost folder first, so a person pastes it
// once and runs the step again. open is in the walk's order (innermost first); "" when it is empty. One folder reads
// as it always did.
func groupRepair(open []groupRefusal) string {
	if len(open) == 0 {
		return ""
	}
	folders := make([]string, len(open))
	subjects := make([]string, len(open))
	reasons := make([]string, len(open))
	sameGroup, sameWhy := true, true
	for i := range open {
		o := open[len(open)-1-i] // outermost first: the order a person reads and pastes them in
		folders[i] = shellword.Quote(o.folder)
		subjects[i] = fmt.Sprintf("group %s (gid %d) for folder %s", record.Printable(o.group), o.gid, folders[i])
		reasons[i] = folders[i] + ": " + record.Printable(o.why)
		sameGroup = sameGroup && o.group == open[0].group && o.gid == open[0].gid
		sameWhy = sameWhy && o.why == open[0].why
	}
	subject := subjects[0]
	if len(open) > 1 {
		if sameGroup {
			subject = fmt.Sprintf("group %s (gid %d) for folders %s", record.Printable(open[0].group), open[0].gid, listWords(folders))
		} else {
			subject = listWords(subjects)
		}
	}
	why := record.Printable(open[0].why)
	if !sameWhy {
		why = strings.Join(reasons, "; and ")
	}
	return fmt.Sprintf("cannot establish membership of %s: %s; no command is shown; run chmod g-w %s, then run this step again.",
		subject, why, strings.Join(folders, " "))
}

// listWords is words as a sentence lists them: "a", "a and b", "a, b and c".
func listWords(words []string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// Path is the running binary's resolved absolute path, with the identity, safe-display and execute checks Named
// uses. It returns raw path bytes for process arguments; Named quotes the result for a shell line. On refusal path is
// empty and why is one of NoPath, Unsafe or NoExec. It never looks on PATH.
func Path(executable func() (string, error)) (path, why string) {
	return checkedPath(executable, procSelfExe)
}

func checkedPath(executable func() (string, error), self string) (path, why string) {
	exe, err := executable()
	if err != nil || exe == "" || !filepath.IsAbs(exe) {
		return "", NoPath
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil || !filepath.IsAbs(real) {
		return "", NoPath
	}
	if !Safe(real) {
		return "", Unsafe
	}
	got, err := os.Stat(real)
	if err != nil || !got.Mode().IsRegular() {
		return "", NoPath
	}
	run, err := os.Stat(self)
	if err != nil || !os.SameFile(got, run) {
		return "", NoPath
	}
	if unix.Access(real, unix.X_OK) != nil {
		return "", NoExec
	}
	return real, ""
}

// Sudo builds a root command from Named's checked shell word. Callers pass only
// fixed arguments or separately quoted, printable words. Failure gives no command.
// named is injectable so every rendering surface can exercise the same refusals.
func Sudo(args string, named func() (string, string)) (command, why string) {
	word, why := named()
	if why != "" {
		return "", why
	}
	if !Safe(args) {
		return "", Unsafe
	}
	return "sudo " + word + " " + args, ""
}
