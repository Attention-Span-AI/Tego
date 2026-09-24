// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestHeldCloseEndsTheListenerBeforeTheDescriptorLimit is the closer's cap against a real group (§6 E35): one
// answered descriptor's close does not return, as a FUSE daemon's or an NFS server's that stopped answering
// would not, and opens go on arriving on the marked mount. Uncapped, every later descriptor waited behind that
// close until the process reached RLIMIT_NOFILE: the kernel then refused a host open itself, the group's read
// failed with EMFILE, and the loop, waiting on the closer, never returned, so the run read its deny_read file
// with no refusal and no line. Now the listener must end at the cap, before any host open is refused: it stops
// reading there, waits one decision deadline for a closer that cannot catch up (fdCloser.catchUp), and returns
// ErrListenerDied without waiting for the held close, which is what has RunListener's caller kill the run (§6
// E15).
//
// The soft limit is lowered to 512 before loop starts, so the cap is 128; it changes this process's limit, so
// the test cannot run in parallel.
func TestHeldCloseEndsTheListenerBeforeTheDescriptorLimit(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(base, "denied")
	if err := os.Mkdir(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	secret, plain := filepath.Join(denied, "secret"), filepath.Join(base, "plain")
	for _, f := range []string{secret, plain} {
		if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rel, id := runCgroup(t, "closer")
	cgdir, err := os.Open(filepath.Join("/sys/fs/cgroup", rel))
	if err != nil {
		t.Fatal(err)
	}
	defer cgdir.Close()
	inRun := func(path string) unix.Errno {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestMovedHelper$")
		cmd.Env = append(os.Environ(), movedHelperEnv+"="+path)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgdir.Fd())}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("helper for %s: %v\n%s", path, err, out)
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			if v, ok := strings.CutPrefix(line, "MOVED-RESULT "); ok {
				n, _ := strconv.Atoi(strings.TrimSpace(v))
				return unix.Errno(n)
			}
		}
		t.Fatalf("helper reported nothing: %s", out)
		return 0
	}

	events := &sink{}
	p := newPolicy(&agent.RuleTable{
		FS:       []agent.FSRule{{Kind: agent.FSDenyRead, Path: denied, Mount: mountOf(t, base), Raw: "deny_read: denied"}},
		Contract: &agent.Contract{},
		Tier:     backend.TierCgroup, Record: agent.RecordFull,
	}, rel)
	l, err := newFanotifyListener(p, Run{ID: "closer", Agent: "a", CgroupID: id, CgroupPath: rel}, events, time.Second)
	if err != nil {
		t.Fatalf("newFanotifyListener: %v", err)
	}
	defer l.Close()
	for _, m := range p.mounts {
		if err := l.markFor(m, p.masks[m]); err != nil {
			t.Fatalf("mark %s: %v", m, err)
		}
	}
	release := make(chan struct{})
	defer close(release)
	held := make(chan struct{})
	first := true
	l.closeSettled = func(fd int) error {
		if first {
			first = false
			close(held)
			<-release // the filesystem stopped answering this close
		}
		return unix.Close(fd)
	}

	var saved unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &saved); err != nil {
		t.Fatal(err)
	}
	lowered := saved
	lowered.Cur = 512
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lowered); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Setrlimit(unix.RLIMIT_NOFILE, &saved) }()
	if got, want := l.closeBacklogLimit(), 128; got != want {
		t.Fatalf("the closer's cap under a soft limit of 512 is %d, want %d", got, want)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	if errno := inRun(secret); errno != unix.EPERM {
		t.Fatalf("before: the run's read of %s got %v, want EPERM", secret, errno)
	}
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("no answered descriptor reached the closer")
	}
	var died error
	opens := 0
	for opens < 5000 && died == nil {
		fd, err := unix.Open(plain, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			select {
			case died = <-loopErr:
				t.Logf("open %d of an allowed file failed after the listener ended: %v", opens, err)
				continue
			default:
			}
			t.Fatalf("host open %d of an allowed file failed with %v while the listener still ran: the process "+
				"reached its descriptor limit behind one held close", opens, err)
		}
		_ = unix.Close(fd)
		opens++
		select {
		case died = <-loopErr:
		default:
		}
	}
	if died == nil {
		select {
		case died = <-loopErr:
		case <-time.After(3 * time.Second):
			t.Fatalf("after %d allowed opens behind one held close the listener still has not returned (marks %v): "+
				"its backlog is not capped, or it waits for the held close before it returns", opens, l.marked())
		}
	}
	if !errors.Is(died, ErrListenerDied) {
		t.Fatalf("loop() = %v, want ErrListenerDied", died)
	}
	t.Logf("the listener ended after %d allowed opens: %v", opens, died)
	if !hasGap(events.all(), GapFanotifyCloseBacklog) {
		t.Fatalf("no %s gap: %+v", GapFanotifyCloseBacklog, events.all())
	}
	if m := l.marked(); len(m) != 0 {
		t.Fatalf("marks %v remain after the listener ended", m)
	}
}

// TestFanotifyAllowedOpensKeepTheListener is the closer's wait at the cap against a real group (§6 E35): opens
// its path allows, arriving as fast as the listener answers them, with no close held, must not end the listener.
// The loop answers them on its own goroutine and blocks nowhere while they keep coming, and this test's goroutine,
// opening, holds the other processor of GOMAXPROCS 2 (a 2-vCPU CI runner's): the closer the loop wakes was not
// run, and its backlog reached the cap with nothing held, after which the run's deny_read file opened. Now the
// loop waits at the cap, the closer catches up, and all 60,000 opens must be answered with the listener still
// running and the deny_read file still refused. With the loop giving the group up at the cap at once, as root in
// the 2-vCPU guest on the runner's 6.17.0-1022-azure, the listener ended in 6 runs of 6, after 2,793 to 38,543
// opens; with the wait, 6 of 6 passed in about 1.1 s each. GOMAXPROCS is the process's, so the test cannot run
// in parallel.
func TestFanotifyAllowedOpensKeepTheListener(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret, plain := filepath.Join(dir, "secret.txt"), filepath.Join(dir, "plain.txt")
	for _, p := range []string{secret, plain} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mount := mountOf(t, dir)
	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skipf("no cgroup v2 path for this process: %v", err)
	}
	events := &sink{}
	p := newPolicy(&agent.RuleTable{
		FS:     []agent.FSRule{{Kind: agent.FSDenyRead, Path: secret, Mount: mount, Raw: "deny_read: secret.txt"}},
		Tier:   backend.TierCgroup,
		Record: agent.RecordFull,
	}, cg)
	l, err := newFanotifyListener(p, Run{ID: "busy", Agent: "a", CgroupPath: cg}, events, time.Second)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
		}
		t.Fatalf("newFanotifyListener: %v", err)
	}
	defer l.Close()
	if err := l.mark(mount); err != nil {
		t.Skipf("marking %s needs CAP_SYS_ADMIN: %v", mount, err)
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	const opens = 60000
	for i := range opens {
		fd, err := unix.Open(plain, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open %d of an allowed file: %v", i, err)
		}
		_ = unix.Close(fd)
		select {
		case err := <-loopErr:
			t.Fatalf("the listener ended after %d allowed opens with no close held: %v", i+1, err)
		default:
		}
	}
	if _, err := os.ReadFile(secret); !errors.Is(err, unix.EPERM) {
		t.Fatalf("after %d allowed opens, the run's read of its deny_read file got %v, want EPERM", opens, err)
	}
	cancel()
	if err := <-loopErr; err != nil {
		t.Fatalf("listener loop: %v", err)
	}
	if hasGap(events.all(), GapFanotifyCloseBacklog) {
		t.Fatalf("a %s gap with no close held: %+v", GapFanotifyCloseBacklog, events.all())
	}
}

// TestUnmarkAllFlushesOnlyTheMountMarks is unmarkAll against a real group (§6 E35). It is one fanotify_mark call
// that names no path, FAN_MARK_FLUSH with FAN_MARK_MOUNT, so that a marked filesystem that stopped answering
// cannot hold a failed listener's return in the path walk FAN_MARK_REMOVE makes. It must remove every mark the
// group holds, all of them mount marks (the group places no inode mark since ADR 0021 (4)), as the group's
// fdinfo lists them, and release the process's arm (ADR 0021 (3)); and an open on the mount must then go through
// with nothing reading the group, where a mark still in place would hold it.
func TestUnmarkAllFlushesOnlyTheMountMarks(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	denied, plain := filepath.Join(base, "denied"), filepath.Join(base, "plain")
	if err := os.Mkdir(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := newPolicy(&agent.RuleTable{
		FS:       []agent.FSRule{{Kind: agent.FSDenyRead, Path: denied, Mount: mountOf(t, base), Raw: "deny_read: denied"}},
		Contract: &agent.Contract{},
		Tier:     backend.TierCgroup, Record: agent.RecordFull,
	}, "/")
	l, err := newFanotifyListener(p, Run{ID: "flush", Agent: "a"}, &sink{}, time.Second)
	if errors.Is(err, unix.EPERM) {
		t.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
	}
	if err != nil {
		t.Fatalf("newFanotifyListener: %v", err)
	}
	defer l.Close()
	if proc.Armed() {
		t.Fatal("a group with no mark armed the process")
	}
	for _, m := range p.mounts {
		if err := l.markFor(m, p.masks[m]); err != nil {
			t.Fatalf("mark %s: %v", m, err)
		}
	}
	listed := func() (mounts, inodes int) {
		t.Helper()
		raw, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", l.fd))
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			switch {
			case strings.HasPrefix(line, "fanotify mnt_id:"):
				mounts++
			case strings.HasPrefix(line, "fanotify ino:"):
				inodes++
			}
		}
		return mounts, inodes
	}
	if mounts, inodes := listed(); mounts != len(p.mounts) || inodes != 0 {
		t.Fatalf("before: the group lists %d mount mark(s) and %d inode mark(s), want %d and none",
			mounts, inodes, len(p.mounts))
	}
	if !proc.Armed() {
		t.Fatal("a group holding marks left the process unarmed: a process start could vfork under them")
	}
	if err := l.unmarkAll(); err != nil {
		t.Fatalf("unmarkAll: %v", err)
	}
	if mounts, inodes := listed(); mounts != 0 || inodes != 0 {
		t.Fatalf("after: the group lists %d mount mark(s) and %d inode mark(s), want none", mounts, inodes)
	}
	if proc.Armed() {
		t.Fatal("the process is still armed with every mark removed")
	}
	opened := make(chan error, 1)
	go func() {
		fd, err := unix.Open(plain, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		if err != nil {
			t.Fatalf("open on the unmarked mount: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("an open on the mount waited on a group nobody reads: its mark is still in place")
	}
}
