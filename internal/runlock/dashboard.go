// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// The dashboard (tego-control serve) is non-dumpable, since it holds the sign-in token and keys (ADR 0100 (7), amended
// 2026-11-22), so a scan from another process of the same user cannot read its program file and counts it among the
// unreadable programs. It is named the way a run's launcher is: the dashboard holds the flock of
// <home>/.tego/dashboard/lock for as long as it lives and writes its pid and start time into that file's one line, and
// DashboardPID proves the line the way `tego stop` proves a launcher's (the kernel's lock table says that pid holds this
// very file's lock; a pidfd checks the start time). The line alone proves nothing.
//
// What this proves is that the process is the one holding the dashboard's lock, no more: a process of the same user
// with no sandbox that takes the lock while no dashboard runs is named too. The scan's own answer says that no program
// of the user's is proved to be an agent (`tego scan`, "Tego cannot tell whether these are agents"), so being named
// here never means "is the real dashboard".

// dashboardDirName is the folder under <home>/.tego that holds the dashboard's lock, named like a run's folder so the
// lock probe and the lock-holder proof read it unchanged.
const dashboardDirName = "dashboard"

// DashboardDir is the folder of the dashboard's lock under home.
func DashboardDir(home string) string { return filepath.Join(home, ".tego", dashboardDirName) }

// dashboardLockWait is how long HoldDashboard waits out a probe's momentary hold of the lock.
const dashboardLockWait = 50 * time.Millisecond

// ErrDashboardHeld is HoldDashboard's answer when another process holds the dashboard's lock.
var ErrDashboardHeld = errors.New("runtime: another dashboard holds the dashboard lock")

// HoldDashboard takes the dashboard's lock under home for this process and records the process in it. The returned file
// is the lock: the caller keeps it open until the process ends, and the kernel frees the lock when the process dies.
func HoldDashboard(home string) (*os.File, error) {
	if !filepath.IsAbs(home) {
		return nil, fmt.Errorf("runtime: dashboard lock: home %q is not an absolute path", home)
	}
	dir := DashboardDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("runtime: dashboard lock folder: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ledger.LockFile), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("runtime: open dashboard lock: %w", err)
	}
	fail := func(err error) (*os.File, error) { _ = f.Close(); return nil, err }
	st, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("runtime: stat dashboard lock: %w", err))
	}
	if !st.Mode().IsRegular() {
		return fail(fmt.Errorf("runtime: dashboard lock %s is not a regular file", f.Name()))
	}
	if raw, ok := st.Sys().(*syscall.Stat_t); !ok || int(raw.Uid) != os.Geteuid() {
		return fail(fmt.Errorf("runtime: dashboard lock %s is not this user's", f.Name()))
	}
	// A scan's probe (ProbeLock) holds the lock for an instant, as it does a run's: wait it out before calling the lock
	// another dashboard's.
	deadline := time.Now().Add(dashboardLockWait)
	for {
		err = sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return fail(fmt.Errorf("runtime: flock dashboard lock: %w", err))
		}
		if time.Now().After(deadline) {
			return fail(ErrDashboardHeld)
		}
		time.Sleep(time.Millisecond)
	}
	start, err := StartBootNS(os.Getpid())
	if err != nil {
		return fail(fmt.Errorf("runtime: dashboard start time: %w", err))
	}
	line := LockInfo{PID: os.Getpid(), StartBootNS: start, PIDNS: OwnPIDNS()}.String()
	if err := f.Truncate(0); err != nil {
		return fail(fmt.Errorf("runtime: write dashboard lock: %w", err))
	}
	if _, err := f.WriteAt([]byte(line), 0); err != nil {
		return fail(fmt.Errorf("runtime: write dashboard lock: %w", err))
	}
	return f, nil
}

// DashboardPID is the pid of the dashboard that holds the dashboard's lock under home, proved as `tego stop` proves a
// launcher: the lock is held, the line names a process that started when it says, and the kernel's lock table shows that
// process holding this file's lock (also when the process is non-dumpable and hides its descriptors). It is 0 and false
// for anything less, never a guess.
func DashboardPID(home string) (int, bool) {
	if !filepath.IsAbs(home) {
		return 0, false
	}
	dir := DashboardDir(home)
	held, info, err := ProbeLock(dir)
	if err != nil || !held || info.PID <= 0 {
		return 0, false
	}
	t, err := OpenStopTargetFor(dir, info)
	if err != nil {
		return 0, false
	}
	_ = t.Close()
	return info.PID, true
}
