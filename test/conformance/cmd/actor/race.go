// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// The TOCTOU harness (ADR 0017 space 4): one thread swaps a symlink between a benign file and the target with
// rename(2) while another opens the link and reads (or writes) through it, raceIters opens or raceBudget,
// whichever ends first. A decision by name made before the open lands would answer the benign file and open the
// target; Landlock and the plane decide by inode and the listener on the opened file, so none should.
const (
	raceIters  = 2000
	raceBudget = 2 * time.Second
)

func init() {
	observers["race-symlink-read"] = func(a Action) (string, error) { return race(a, false) }
	observers["race-symlink-write"] = func(a Action) (string, error) { return race(a, true) }
}

// race runs the harness on Path (the link it makes, inside a write entry) and Dest (the target). Its value counts
// the opens. It succeeds when a byte of the target was read, or written, through the link: the fail-open the cell
// exists to catch. It fails with the errno of the refusals when the target was opened through the link never and
// refused at least once while benign opens went through, so the race interleaved; any other count is no answer
// (an error with no errno), since a run that never met the target, or never the benign file, raced nothing.
func race(a Action, write bool) (string, error) {
	target, err := filepath.Abs(a.Dest)
	if err != nil {
		return "", err
	}
	var tst unix.Stat_t
	if err := unix.Stat(target, &tst); err != nil {
		return "", fmt.Errorf("stat the target: %w", err)
	}
	benign, err := filepath.Abs(a.Path + ".benign")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(benign, []byte("benign\n"), 0o644); err != nil {
		return "", fmt.Errorf("the benign file: %w", err)
	}
	if err := swapTo(benign, a.Path); err != nil {
		return "", fmt.Errorf("the link: %w", err)
	}
	var stop atomic.Bool
	swapErr := make(chan error, 1)
	go func() {
		runtime.LockOSThread()                             // its own thread, so the swap runs beside the opens
		for i := 0; !stop.Load() && i < 4*raceIters; i++ { // bounded: each swap is two lines of a full record
			to := benign
			if i%2 == 1 {
				to = target
			}
			if err := swapTo(to, a.Path); err != nil {
				swapErr <- err
				return
			}
		}
		swapErr <- nil
	}()
	flags, buf := unix.O_RDONLY, make([]byte, 1)
	if write {
		flags, buf[0] = unix.O_WRONLY|unix.O_APPEND, '\n'
	}
	var opens, benignOpens, hits, refused, other int
	var refusal unix.Errno
	for deadline := time.Now().Add(raceBudget); opens < raceIters && time.Now().Before(deadline); opens++ {
		fd, err := unix.Open(a.Path, flags|unix.O_CLOEXEC, 0)
		var en unix.Errno
		switch {
		case errors.As(err, &en) && (en == unix.EACCES || en == unix.EPERM):
			refused, refusal = refused+1, en
			continue
		case err != nil:
			other++
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && st.Dev == tst.Dev && st.Ino == tst.Ino {
			var n int
			if write {
				n, err = unix.Write(fd, buf)
			} else {
				n, err = unix.Read(fd, buf)
			}
			if err == nil && n == 1 {
				hits++
			}
		} else {
			benignOpens++
		}
		_ = unix.Close(fd)
	}
	stop.Store(true)
	if err := <-swapErr; err != nil {
		return "", fmt.Errorf("the swap: %w", err)
	}
	value := fmt.Sprintf("opens=%d benign=%d target=%d refused=%d other=%d", opens, benignOpens, hits, refused, other)
	switch {
	case hits > 0:
		return value, nil
	case refused > 0 && benignOpens > 0:
		return value, refusal
	}
	return value, fmt.Errorf("the race did not interleave: %s", value)
}

// swapTo points link at to in one rename(2), so an open of link always finds one of the two.
func swapTo(to, link string) error {
	tmp := link + ".swap"
	if err := os.Symlink(to, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}
