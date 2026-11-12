// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// maxAncestors bounds StartedByAnother's walk: sudo, its monitor and the shell sudo was typed in are three steps up.
const maxAncestors = 16

// overflowUID is the uid /proc shows for a process whose uid has no mapping in the reader's user namespace (the
// kernel's default overflowuid): not a user who typed anything.
const overflowUID = 65534

// StartedByAnother reports whether the process pid, which runs as uid, was started from the shell of another user,
// through sudo, su or the like, so the person who reads a command it prints types it as that other user (acceptance 3,
// 2026-11-11: an administrator typed sudo -u svc tego setup, then the printed scope command in their own shell). proc
// is the procfs root, /proc outside tests. Two facts say so, and neither comes from the environment: the process's
// login uid (<proc>/<pid>/loginuid, which pam_loginuid sets at an SSH, console or desktop login and sudo and su keep)
// is set and is not uid; or, walking its ancestors (<proc>/<pid>/status, at most maxAncestors steps, up to pid 1), the
// first one whose real uid is neither uid nor root (the shell sudo or su was typed in, above sudo's or su's root
// processes). A process of uid cannot change its ancestors' uids. It can set its own login uid once while that is
// unset, without privilege (the kernel's audit_set_loginuid_perm: an unset login uid needs no privilege to set; read,
// not run), so a process of uid with an unset login uid can make the answer true. That only selects which of two
// commands is printed, and both are built from fixed words, the passwd entry and numbers. An ancestor it cannot read,
// one shown as overflowUID, or no such fact, is false: the reader is taken to be uid. SUDO_UID is not read: any
// process of uid can set it, and the two facts answer without it.
func StartedByAnother(proc string, pid, uid int) bool {
	if b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "loginuid")); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil && n != 0xffffffff && int(n) != uid {
			return true
		}
	}
	_, p, ok := procStatus(proc, pid)
	for range maxAncestors {
		if !ok || p <= 1 {
			return false
		}
		var ruid int
		ruid, p, ok = procStatus(proc, p)
		if ok && ruid == overflowUID {
			return false // a process of another user namespace: whose it is is not known here
		}
		if ok && ruid != uid && ruid != 0 {
			return true
		}
	}
	return false
}

// ReadByAnother is StartedByAnother for this process and its real uid, false when its real and effective uids differ
// (whose command to print is then not known, and the caller's own refusal or the reader-is-uid form applies).
func ReadByAnother() bool {
	uid := os.Getuid()
	return uid == os.Geteuid() && StartedByAnother("/proc", os.Getpid(), uid)
}

// procStatus is the real uid and the parent of pid, from <proc>/<pid>/status's Uid: and PPid: lines.
func procStatus(proc string, pid int) (ruid, ppid int, ok bool) {
	b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, 0, false
	}
	var haveUID, havePPID bool
	for _, line := range strings.Split(string(b), "\n") {
		key, value, found := strings.Cut(line, ":")
		f := strings.Fields(value)
		if !found || len(f) == 0 {
			continue
		}
		switch key {
		case "Uid":
			ruid, err = strconv.Atoi(f[0])
			haveUID = err == nil
		case "PPid":
			ppid, err = strconv.Atoi(f[0])
			havePPID = err == nil
		}
	}
	return ruid, ppid, haveUID && havePPID
}
