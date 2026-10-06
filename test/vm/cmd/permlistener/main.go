// SPDX-License-Identifier: Apache-2.0

// Command permlistener is a third-party fanotify permission listener, for the runs that have to show Tego's own
// fanotify group (tier cgroup's fallback, enforce-cgroup-observe §6 E34) coexists with someone else's. It is a
// test tool: nothing in the engine imports it, and it is built for the KVM guests (test/vm/README.md).
//
//	permlistener [-mode allow-touch] [-mark PATH]... [-workers N] [-touch FILE]... [-stat PATH]...
//	             [-decide-delay D] [-deadline D]
//	permlistener -mode deny -path P [-mark PATH]...
//
// allow-touch is ADR 0021's third-party listener: "a permission listener whose decisions open files on `/`". It
// marks the mount of each -mark (default /) for FAN_OPEN_PERM and FAN_OPEN_EXEC_PERM, and each open or exec by
// another process is decided by one of N workers, which waits -decide-delay (default 2 ms, to widen the window),
// opens and reads each -touch file (default /etc/os-release), stats each -stat path (default /usr/bin) and
// answers FAN_ALLOW. That is the cycle ADR 0021 names: the opener of the stage waits on this group, this group's
// decision waits on an open that Tego's group on the same mount has to answer, and Tego's launcher cannot
// answer while it is in a vfork window. The listener's own opens, which its workers make, are allowed on the
// reader at once; a worker waits for that answer, so the reader can never wait for a worker.
//
// deny is ADR 0017's space 6: a listener that refuses one file. It marks the mount of -path's directory (or each
// -mark) for FAN_OPEN_PERM and answers FAN_DENY to every open of P, by name or by inode, so the opener's open
// fails EPERM, and FAN_ALLOW to all else, at once. It opens nothing itself.
//
// Both modes: an event not answered within -deadline (allow-touch, default 10 s) is answered FAN_ALLOW and
// counted late, so the helper is never the stall it provokes. On SIGTERM or SIGINT the marks come down first,
// whatever is still in the group is answered, and the group closes. SIGKILL leaves the kernel to release it,
// which is E15's case.
//
// Output, one line each, on stdout (diagnostics go to stderr, prefixed "permlistener:"):
//
//	PERMLISTENER-READY
//	PERMLISTENER-STATS events=N tego=N self=N late=N denied=N exec=N failed=N malformed=N mode=M
//
// READY is printed once every mark is placed. STATS is the last line, printed after the group closed; the fields
// are on the stats type. Exit status 0 is a clean stop, 1 a failed start or a group that stopped working, 2 a
// usage error.
//
// It needs CAP_SYS_ADMIN and a Linux 5.0+ kernel (FAN_OPEN_EXEC_PERM). It is built CGO-off, so the guests, which
// carry no libc for it, run the same file; it cross-builds for arm64.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Exit codes.
const (
	exitFailed = 1
	exitUsage  = 2
)

func main() {
	// A reader of our stdout that goes away must not kill the listener with SIGPIPE: the group's marks would
	// vanish with it, and an open it was holding would be let through, unanswered.
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// group is a fanotify group with its marks placed: the descriptor to read and answer on, and the call that
// removes every mark it holds.
type group struct {
	fd     int
	unmark func() error
}

// openGroup creates the group and places the marks. A variable so the tests can put a socketpair where the
// kernel would be.
var openGroup = func(cfg config) (group, error) {
	// FAN_UNLIMITED_QUEUE: a burst of opens must not overflow the queue, whose overflow lets permission events
	// through unanswered and would make the counts unreliable. FAN_NONBLOCK: the reader polls.
	const flags = unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_NONBLOCK | unix.FAN_UNLIMITED_QUEUE
	fd, err := unix.FanotifyInit(flags, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_LARGEFILE)
	if err != nil {
		return group{}, fmt.Errorf("fanotify_init: %w%s", err, initHint(err))
	}
	mask := uint64(unix.FAN_OPEN_PERM)
	if cfg.mode == modeAllowTouch {
		mask |= unix.FAN_OPEN_EXEC_PERM
	}
	for _, m := range cfg.marks {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, m); err != nil {
			_ = unix.Close(fd)
			return group{}, fmt.Errorf("fanotify_mark %s: %w", m, err)
		}
	}
	return group{fd: fd, unmark: func() error {
		// Naming no path, so it waits on no filesystem, whatever the marked mounts are doing.
		return unix.FanotifyMark(fd, unix.FAN_MARK_FLUSH|unix.FAN_MARK_MOUNT, 0, unix.AT_FDCWD, "")
	}}, nil
}

func initHint(err error) string {
	switch {
	case errors.Is(err, unix.EPERM):
		return " (a fanotify permission group needs CAP_SYS_ADMIN)"
	case errors.Is(err, unix.EMFILE):
		return " (fs.fanotify.max_user_groups is used up, or no descriptor is left)"
	case errors.Is(err, unix.ENOSYS):
		return " (this kernel has no fanotify)"
	}
	return ""
}

// run is the command: it returns the exit status. It stops when ctx ends or the reader fails.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := parseConfig(args, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		fmt.Fprintf(stderr, "permlistener: %v\n", err)
		return exitUsage
	}
	if err := preflight(cfg); err != nil {
		fmt.Fprintf(stderr, "permlistener: %v\n", err)
		return exitFailed
	}
	g, err := openGroup(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "permlistener: %v\n", err)
		return exitFailed
	}
	l, err := newListener(cfg, g.fd)
	if err != nil {
		_ = unix.Close(g.fd)
		fmt.Fprintf(stderr, "permlistener: %v\n", err)
		return exitFailed
	}
	l.unmark = g.unmark
	l.logf = func(format string, args ...any) { fmt.Fprintf(stderr, "permlistener: "+format+"\n", args...) }
	l.start()
	l.logf("%s, pid %d, marking %s", cfg.mode, os.Getpid(), strings.Join(cfg.marks, ", "))
	fmt.Fprintln(stdout, "PERMLISTENER-READY")

	select {
	case <-ctx.Done():
	case <-l.readerDone:
	}
	st := l.stop()
	fmt.Fprintln(stdout, st)
	if l.err() != nil {
		return exitFailed
	}
	return 0
}
