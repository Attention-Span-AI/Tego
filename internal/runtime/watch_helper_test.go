// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// watchArg selects watchHelper: the test binary run as `<binary> watch <target> <beside>` inside a run.
const watchArg = "watch"

// Exit codes of watchHelper beyond 0, every watch answered as the run withholds reads.
const (
	watchExitTargetWatched  = 3  // an inotify watch of the deny_read target was made
	watchExitTargetErrno    = 4  // it failed, but not with EACCES
	watchExitBesideRefused  = 5  // the watch of the directory beside the target failed
	watchExitMarkWatched    = 6  // a fanotify inode mark of the target was made
	watchExitMarkErrno      = 7  // it failed, but not with EACCES
	watchExitDnotifyWatched = 8  // a dnotify watch (fcntl F_NOTIFY) of a descriptor of the target was made
	watchExitHelper         = 9  // the helper itself failed
	watchExitDnotifyErrno   = 10 // the dnotify watch failed, but not with EACCES
	watchExitDnotifyOpen    = 11 // the target could not be opened to list, so no dnotify watch was tried
	watchExitDnotifyBeside  = 12 // the dnotify watch of the directory beside the target failed
)

// dnotify's mask bits (linux/fcntl.h), which golang.org/x/sys/unix does not define.
const (
	dnAccess    = 0x1
	dnModify    = 0x2
	dnMultishot = 0x80000000
)

// watchHelper is the agent of TestIntegrationAWatchOfADenyReadTargetIsRefused: it watches the deny_read target with
// inotify, which must fail EACCES, then the directory beside it, which must succeed; then it opens the target to list
// (the READ_DIR a tier-1 ruleset leaves it) and asks a dnotify watch of that descriptor, which must fail EACCES, and one
// of the directory beside it, which must succeed; and, where the kernel lets an unprivileged process make a fanotify
// group, it marks the target, which must fail EACCES too. It exits with the first code that says otherwise, 0 when
// none does. It returns at once when the binary was not started as the helper, and never returns when it was.
func watchHelper() {
	if len(os.Args) != 4 || os.Args[1] != watchArg {
		return
	}
	target, beside := os.Args[2], os.Args[3]
	in, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inotify_init1: %v\n", err)
		os.Exit(watchExitHelper)
	}
	_, err = unix.InotifyAddWatch(in, target, unix.IN_ALL_EVENTS)
	switch {
	case err == nil:
		os.Exit(watchExitTargetWatched)
	case !errors.Is(err, unix.EACCES):
		fmt.Fprintf(os.Stderr, "inotify_add_watch %s: %v\n", target, err)
		os.Exit(watchExitTargetErrno)
	}
	if _, err := unix.InotifyAddWatch(in, beside, unix.IN_ALL_EVENTS); err != nil {
		fmt.Fprintf(os.Stderr, "inotify_add_watch %s: %v\n", beside, err)
		os.Exit(watchExitBesideRefused)
	}
	if code := dnotifyWatch(target, beside); code != 0 {
		os.Exit(code)
	}
	fan, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_FID|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		os.Exit(0) // no unprivileged fanotify group on this kernel: nothing more to watch with
	}
	err = unix.FanotifyMark(fan, unix.FAN_MARK_ADD, unix.FAN_OPEN|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, target)
	switch {
	case err == nil:
		os.Exit(watchExitMarkWatched)
	case !errors.Is(err, unix.EACCES):
		fmt.Fprintf(os.Stderr, "fanotify_mark %s: %v\n", target, err)
		os.Exit(watchExitMarkErrno)
	}
	os.Exit(0)
}

// dnotifyWatch is watchHelper's dnotify half: a watch of a descriptor of target, opened to list, must fail EACCES, and
// one of beside must be made. Each descriptor is closed at once, which drops its watch, so no event is ever sent. It
// returns the exit code that says otherwise, 0 when none does.
func dnotifyWatch(target, beside string) int {
	for _, w := range []struct {
		dir    string
		denied bool
	}{{target, true}, {beside, false}} {
		fd, err := unix.Open(w.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open %s to list: %v\n", w.dir, err)
			if w.denied {
				return watchExitDnotifyOpen
			}
			return watchExitDnotifyBeside
		}
		_, err = unix.FcntlInt(uintptr(fd), unix.F_NOTIFY, dnAccess|dnModify|dnMultishot)
		_ = unix.Close(fd)
		switch {
		case !w.denied && err != nil:
			fmt.Fprintf(os.Stderr, "fcntl F_NOTIFY %s: %v\n", w.dir, err)
			return watchExitDnotifyBeside
		case w.denied && err == nil:
			return watchExitDnotifyWatched
		case w.denied && !errors.Is(err, unix.EACCES):
			fmt.Fprintf(os.Stderr, "fcntl F_NOTIFY %s: %v\n", w.dir, err)
			return watchExitDnotifyErrno
		}
	}
	return 0
}
