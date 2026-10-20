// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestParseProcLocksReadsHeldFlocksOnly is the lock-table parser a re-arm pass reads a timer's liveness with (ADR
// 0022, note 2026-10-06), on the lines the kernel prints from 5.14 to 7.x: a held flock is read with its kind, pid,
// device and inode; a waiter's line ("->", indented by its depth since 5.15), a POSIX or OFD lock, a lease and a lock
// with no inode are not.
func TestParseProcLocksReadsHeldFlocksOnly(t *testing.T) {
	t.Parallel()
	table := strings.Join([]string{
		"1: FLOCK  ADVISORY  WRITE 1234 00:1a:5678 0 EOF",
		"1: -> FLOCK  ADVISORY  WRITE 4321 00:1a:5678 0 EOF",
		"1:  -> FLOCK  ADVISORY  WRITE 4322 00:1a:5678 0 EOF",
		"2: POSIX  ADVISORY  READ 787335 103:02:11156029 128 128",
		"3: OFDLCK ADVISORY  WRITE -1 00:05:12 0 EOF",
		"4: LEASE  ACTIVE    READ 77 00:1a:3 0 EOF",
		"5: FLOCK  ADVISORY  WRITE 0 <none>:0 0 EOF",
		"6: FLOCK  ADVISORY  READ 0 103:02:11144742 0 EOF",
		"garbage",
		"7: FLOCK  ADVISORY  UNLCK 9 00:1a:1 0 EOF",
	}, "\n")
	got := parseProcLocks([]byte(table))
	want := []procLock{
		{write: true, pid: 1234, major: 0, minor: 0x1a, ino: 5678},
		{write: false, pid: 0, major: 0x103, minor: 2, ino: 11144742},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseProcLocks = %+v, want %+v", got, want)
	}
}

// TestTheLockTableShowsAHeldFlock reads the running kernel's /proc/locks: an exclusive flock this process takes is
// there as held for writing, a shared one as held but not for writing, and neither once let go. It is what a re-arm
// pass reads instead of taking a timer's or a launcher's lock.
func TestTheLockTableShowsAHeldFlock(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bpf-x.timer")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	look := func(write bool) bool {
		t.Helper()
		b, err := procLocksTable()
		if err != nil {
			t.Fatalf("read the lock table: %v", err)
		}
		return heldOn(parseProcLocks(b), st, write)
	}
	if look(false) {
		t.Fatal("a file no one locked is listed as held")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if !look(true) {
		t.Fatal("an exclusive flock is not listed as held for writing")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	if look(true) || !look(false) {
		t.Fatalf("a shared flock: held for writing %v, held %v; want false, true", look(true), look(false))
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if look(false) {
		t.Fatal("a flock let go is still listed as held")
	}
}

// rearmHost is a bpf filesystem and a state directory standing in for the host's, with builds planted in them, and
// the timer processes that are alive, by pid.
type rearmHost struct {
	t            *testing.T
	bpffs, state string
	now          time.Time
	alive        map[int]string
}

// timer writes pid into build hash's timer file, as its timer does, and makes it a live timer of hash when alive.
func (r rearmHost) timer(hash string, pid int, alive bool) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.state, "bpf-"+hash+".timer"), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
	if alive {
		r.alive[pid] = hash
	}
}

// build makes build hash's pins and its lock, idle for idle, and returns its pin directory.
func (r rearmHost) build(hash string, idle time.Duration) string {
	r.t.Helper()
	return timerBuild(r.t, r.bpffs, r.state, hash, r.now.Add(-idle))
}

// flock opens name in the state directory and locks it how; the lock is let go at the test's end.
func (r rearmHost) flock(name string, how int) {
	r.t.Helper()
	f, err := os.OpenFile(filepath.Join(r.state, name), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = f.Close() })
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		r.t.Fatal(err)
	}
}

// rearm runs a re-arm pass whose timer starts are recorded and fail with startErr: Prepare's (expired builds only,
// no lock table) when prepare, else stop's, which reads table, nil meaning the kernel's (procLocksTable).
func (r rearmHost) rearm(prepare bool, startErr error, table func() ([]byte, error)) (started []string, states []BuildState, err error) {
	r.t.Helper()
	opts := SweepOptions{BPFFS: r.bpffs, StateDir: r.state, CgroupMount: r.t.TempDir(), Linger: time.Hour,
		ExpiredOnly: prepare, Now: func() time.Time { return r.now },
		timerProcess: func(pid int, hash string) bool { return r.alive[pid] == hash }}
	if prepare {
		table = nil
	} else if table == nil {
		table = procLocksTable
	}
	states, err = rearmTimers(opts, "", table, func(hash string) error {
		started = append(started, hash)
		return startErr
	})
	slices.Sort(started)
	return started, states, err
}

func newRearmHost(t *testing.T) rearmHost {
	return rearmHost{t: t, bpffs: t.TempDir(), state: t.TempDir(), now: time.Unix(1_700_000_000, 0), alive: map[int]string{}}
}

// TestRearmTimersStartsTheTimerOfEveryBuildWithout is `tego stop`'s pass (ADR 0022 (4), (8)): every build that no
// launcher holds and whose timer is not running gets its timer, inside its linger as well as past it, since (8)
// bounds a build's stay only while its timer lives; so does a build gone with its plane directory left, whose
// links the timer's sweep removes, and one whose timer file names a pid that is no timer now. A build whose timer
// file names a live timer gets none; for the rest the kernel's lock table is read, and a build a launcher holds,
// and one whose timer lock is held by a timer that wrote no pid (an older tego's), get none. Nothing is removed.
//
// Prepare's form (note 2026-10-16) re-arms only builds idle past the linger (the gone one, whose lock no launcher
// stamped, counts as expired) and reads no lock table, whose read waits for an RCU grace period: it goes by the pid
// alone, so the held build and the one with an older tego's timer get a timer too, which waits for its launcher or
// exits on the timer lock.
func TestRearmTimersStartsTheTimerOfEveryBuildWithout(t *testing.T) {
	t.Parallel()
	r := newRearmHost(t)
	roots := []string{r.build("lingering", time.Minute), r.build("expired", 2*time.Hour),
		r.build("timed", 2*time.Hour), r.build("held", 2*time.Hour), r.build("pidtimed", 2*time.Hour),
		r.build("deadpid", 2*time.Hour)}
	r.flock("bpf-timed.timer", unix.LOCK_EX)
	r.flock("bpf-held.lock", unix.LOCK_SH)
	r.timer("pidtimed", 4242, true)
	r.timer("deadpid", 4343, false)
	plane := filepath.Join(r.bpffs, pinRoot, planeDirName("gone", "lsm"))
	if err := os.MkdirAll(plane, 0o700); err != nil {
		t.Fatal(err)
	}
	reads := 0
	started, states, err := r.rearm(false, nil, func() ([]byte, error) { reads++; return procLocksTable() })
	if err != nil {
		t.Fatalf("rearmTimers: %v", err)
	}
	if want := []string{"deadpid", "expired", "gone", "lingering"}; !slices.Equal(started, want) {
		t.Errorf("timers started: %v, want %v", started, want)
	}
	if reads != 1 {
		t.Errorf("stop's pass read the lock table %d times, want once", reads)
	}
	why := map[string]string{}
	for _, s := range states {
		why[s.Hash] = s.Why
		if s.Rearmed != (s.Why == whyRearmed) || s.Removed {
			t.Errorf("%s: %+v", s.Hash, s)
		}
	}
	if why["timed"] != whyTimed || why["held"] != whyBusy || why["pidtimed"] != whyTimed {
		t.Errorf("reasons %v: want timed and pidtimed %q, held %q", why, whyTimed, whyBusy)
	}
	for _, root := range append(roots, plane) {
		if _, err := os.Stat(root); err != nil {
			t.Errorf("a re-arm pass removed %s: %v", root, err)
		}
	}
	want := []string{"deadpid", "expired", "gone", "held", "timed"}
	if started, _, _ := r.rearm(true, nil, nil); !slices.Equal(started, want) {
		t.Errorf("Prepare's pass started %v, want %v", started, want)
	}
}

// TestRearmTimersReadsTheLockTableOnlyForABuildWithNoTimerShown: stop's pass reads the kernel's lock table, which
// waits for an RCU grace period, only when a build's timer file shows no live timer; on a host whose lingering
// builds all have theirs it reads none.
func TestRearmTimersReadsTheLockTableOnlyForABuildWithNoTimerShown(t *testing.T) {
	t.Parallel()
	r := newRearmHost(t)
	r.build("a", 2*time.Hour)
	r.build("b", time.Minute)
	r.timer("a", 4242, true)
	r.timer("b", 4343, true)
	reads := 0
	started, _, err := r.rearm(false, nil, func() ([]byte, error) { reads++; return nil, nil })
	if err != nil || len(started) != 0 || reads != 0 {
		t.Errorf("started %v, %d lock-table reads, %v; want none, none, nil", started, reads, err)
	}
}

// TestRearmTimersStartsATimerWhenTheLockTableCannotBeRead: a table that cannot be read shows no holder, so the pass
// starts a timer for every build it would otherwise ask about, a timed one too; the timer that was running keeps its
// timer lock and the new one exits (TestASecondTimerOfABuildExitsAtOnce), which costs an exec, where trusting no
// timer to be running costs nothing to the build's bound.
func TestRearmTimersStartsATimerWhenTheLockTableCannotBeRead(t *testing.T) {
	t.Parallel()
	r := newRearmHost(t)
	r.build("expired", 2*time.Hour)
	r.build("timed", 2*time.Hour)
	r.flock("bpf-timed.timer", unix.LOCK_EX)
	started, _, _ := r.rearm(false, nil, func() ([]byte, error) { return nil, errors.New("EACCES") })
	if want := []string{"expired", "timed"}; !slices.Equal(started, want) {
		t.Errorf("timers started: %v, want %v", started, want)
	}
}

// TestIsTimerProcessReadsUidsAndCommandLine is the pid reading Prepare uses for a timer's liveness (note 2026-10-16):
// a process is build hash's timer only when its command line is <exe> __bpf-linger hash and all four of its uids are
// root's. A user's process can carry any command line, and one that made itself undumpable has a /proc directory
// owned by root, but its uids in status are its own. A pid with no directory, a command line for another build or
// another command, and a command line over 4 KiB are not timers.
func TestIsTimerProcessReadsUidsAndCommandLine(t *testing.T) {
	t.Parallel()
	proc := t.TempDir()
	plant := func(pid int, cmdline, uids string) {
		t.Helper()
		dir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		status := "Name:\ttego\nState:\tS (sleeping)\nUid:\t" + uids + "\nGid:\t0\t0\t0\t0\n"
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	argv := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	timer := argv("/usr/bin/tego", LingerCommand, "h1", "5m0s", "/sys/fs/bpf", "/run/tego")
	plant(10, timer, "0\t0\t0\t0")
	plant(11, timer, "1000\t1000\t1000\t1000")
	plant(12, timer, "1000\t0\t0\t0")
	plant(13, argv("/usr/bin/tego", "run", "h1"), "0\t0\t0\t0")
	plant(14, argv("/usr/bin/tego", LingerCommand, "h1", strings.Repeat("x", 5000)), "0\t0\t0\t0")
	plant(15, timer, "0\t0\t0")
	for _, c := range []struct {
		pid  int
		hash string
		want bool
	}{
		{10, "h1", true}, {10, "h2", false}, {11, "h1", false}, {12, "h1", false}, {13, "h1", false},
		{14, "h1", false}, {15, "h1", false}, {16, "h1", false},
	} {
		if got := isTimerProcess(proc, c.pid, c.hash, 0); got != c.want {
			t.Errorf("isTimerProcess(%d, %s) = %v, want %v", c.pid, c.hash, got, c.want)
		}
	}
	if !isTimerProcess(proc, 11, "h1", 1000) {
		t.Error("a timer of uid 1000 is not one when uid 1000 is asked for")
	}
}

// fakeTimerEnv makes this test binary a stand-in timer process (TestMain): it waits for its standard input to close.
const fakeTimerEnv = "TEGO_TEST_FAKE_TIMER"

// TestIsTimerProcessKnowsARealTimer reads a real process's /proc: this test binary re-executed with the command line
// of a timer of build h1 is h1's timer by its own uid, and not h2's; this process, whose command line is the test
// binary's, is no timer; and the pid a real timer lock writes into its timer file is what timerRunning reads.
func TestIsTimerProcessKnowsARealTimer(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := &exec.Cmd{Path: self, Args: []string{"tego", LingerCommand, "h1", "5m0s"}, Stdin: in,
		Env: append(os.Environ(), fakeTimerEnv+"=1")}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	defer func() { _ = out.Close(); _ = cmd.Wait() }()
	uid := uint32(os.Getuid())
	// Start returns once execve has closed the close-on-exec pipe, before the new image's command line is set up: a
	// timer is read as one only from then on (a Prepare in that moment starts a second, which exits on the lock).
	for deadline := time.Now().Add(5 * time.Second); !isTimerProcess(procRoot, cmd.Process.Pid, "h1", uid) && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if !isTimerProcess(procRoot, cmd.Process.Pid, "h1", uid) || isTimerProcess(procRoot, cmd.Process.Pid, "h2", uid) {
		t.Errorf("the stand-in timer of h1: h1's %v, h2's %v; want true, false",
			isTimerProcess(procRoot, cmd.Process.Pid, "h1", uid), isTimerProcess(procRoot, cmd.Process.Pid, "h2", uid))
	}
	if isTimerProcess(procRoot, os.Getpid(), "h1", uid) {
		t.Error("the test binary itself reads as a timer")
	}
	if os.Geteuid() != 0 && isTimerProcess(procRoot, cmd.Process.Pid, "h1", 0) {
		t.Error("a process of uid", uid, "reads as root's timer")
	}

	d, err := hoststate.OpenAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	f, busy, err := lockTimer(d, "h1")
	if err != nil || busy {
		t.Fatalf("lockTimer: busy %v, %v", busy, err)
	}
	defer f.Close()
	var named int
	if !timerRunning(d, "h1", func(pid int, _ string) bool { named = pid; return true }) || named != os.Getpid() {
		t.Errorf("timerRunning read pid %d from the timer file, want this process's %d", named, os.Getpid())
	}
	if timerRunning(d, "h2", func(int, string) bool { return true }) {
		t.Error("a build with no timer file has a timer running")
	}
}

// TestRearmTimersSweepsABuildWhoseTimerCannotStart: a build whose timer cannot be started is removed by the pass
// itself, past its linger only, and the start's error is returned; a test binary's errNoTimer is not an error.
func TestRearmTimersSweepsABuildWhoseTimerCannotStart(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err     error
		wantErr bool
	}{{errors.New("exec: no tego"), true}, {errNoTimer, false}} {
		r := newRearmHost(t)
		expired, lingering := r.build("expired", 2*time.Hour), r.build("lingering", time.Minute)
		_, states, err := r.rearm(false, c.err, nil)
		if (err != nil) != c.wantErr {
			t.Errorf("start error %v: rearmTimers error %v, want one: %v", c.err, err, c.wantErr)
		}
		if _, err := os.Stat(expired); !os.IsNotExist(err) {
			t.Errorf("start error %v: the expired build is still pinned: %v", c.err, err)
		}
		if _, err := os.Stat(lingering); err != nil {
			t.Errorf("start error %v: the lingering build was removed: %v", c.err, err)
		}
		for _, s := range states {
			if s.Hash == "expired" && !s.Removed {
				t.Errorf("start error %v: the expired build's state %+v says it was kept", c.err, s)
			}
		}
	}
}

// TestTheTimerWritesItsPidIntoItsTimerFile: the timer's pid is in bpf-<hash>.timer while it holds it, replacing
// whatever was there: it is Prepare's reading of the timer's liveness (timerRunning), and stop's pass reads the
// kernel's lock table only for a build whose file shows no live timer.
func TestTheTimerWritesItsPidIntoItsTimerFile(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := os.WriteFile(filepath.Join(state, "bpf-tp.timer"), []byte("99999999 stale and longer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, busy, err := lockTimer(d, "tp")
	if err != nil || busy {
		t.Fatalf("lockTimer: busy %v, %v", busy, err)
	}
	defer f.Close()
	b, err := os.ReadFile(filepath.Join(state, "bpf-tp.timer"))
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.Itoa(os.Getpid()) + "\n"; string(b) != want {
		t.Errorf("the timer file reads %q, want %q", b, want)
	}
}

// TestATimerAsksForABusyTimerLockOnceMore: a sweep's removeStaleState holds a timer file's lock for a moment, and a
// timer a re-arm pass started in that moment exited, leaving its build with no timer. It now asks once more a moment
// later and, given the lock, keeps its build.
func TestATimerAsksForABusyTimerLockOnceMore(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	root := timerBuild(t, bpffs, state, "tr", c.at.Add(-2*time.Hour))
	probe, err := os.OpenFile(filepath.Join(state, "bpf-tr.timer"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	clock := c.clock()
	clock.retry = func() { _ = probe.Close() } // the probe lets go
	if code := runTimer("tr", time.Minute, bpffs, state, clock); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the timer exited on a probe's moment and left its build: %v", err)
	}
}

// TestRearmTimersStartsNoTestBinaryAsATimer: `tego stop` passes its own image, /proc/self/exe, as the timer's
// binary, and a root stop in a Go test binary (internal/cli's tests in the KVM guest) would have started that binary,
// detached and as root, as the timer: re-executed with LingerCommand it runs its whole suite. A test binary starts no
// timer (errNoTimer), as a run that names no stage binary in one does (startTimerFor), and a build past its linger
// is removed by the pass itself, as the timer would; a named tego binary is started.
func TestRearmTimersStartsNoTestBinaryAsATimer(t *testing.T) {
	var started []string
	saved := startHelperProcess
	startHelperProcess = func(exe string, _ ...string) error { started = append(started, exe); return nil }
	t.Cleanup(func() { startHelperProcess = saved })
	r := newRearmHost(t)
	expired, lingering := r.build("expired", 2*time.Hour), r.build("lingering", time.Minute)
	opts := SweepOptions{BPFFS: r.bpffs, StateDir: r.state, CgroupMount: t.TempDir(), Linger: time.Hour,
		Now: func() time.Time { return r.now }, lockTable: func() ([]byte, error) { return nil, nil }}
	states, err := RearmTimers(opts, "/proc/self/exe")
	if err != nil {
		t.Fatalf("RearmTimers: %v", err)
	}
	if len(started) != 0 {
		t.Fatalf("a test binary started %v as a build's timer", started)
	}
	if _, err := os.Stat(expired); !os.IsNotExist(err) {
		t.Errorf("the expired build is still pinned: %v (states %+v)", err, states)
	}
	if _, err := os.Stat(lingering); err != nil {
		t.Errorf("the lingering build was removed: %v", err)
	}
	if _, err := RearmTimers(opts, "/usr/bin/tego"); err != nil {
		t.Fatalf("RearmTimers: %v", err)
	}
	if !slices.Equal(started, []string{"/usr/bin/tego"}) {
		t.Errorf("a named tego binary: started %v, want the lingering build's timer from /usr/bin/tego", started)
	}
}
