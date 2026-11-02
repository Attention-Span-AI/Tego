// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// fileFreeze is cgroup v2's freezer (5.2+): "1" freezes every task of the cgroup and its descendants, "0" thaws
// them. cgroup.events' "frozen" line says when the freeze is complete.
const fileFreeze = "cgroup.freeze"

// FreezeWait bounds a wait for a freeze or a thaw: a freeze completes once every task has left the kernel, which takes milliseconds
// (8.6 ms measured on a looping agent). A task in a wait the freezer cannot enter holds it for as long as that wait
// lasts: uninterruptible sleep, and a seccomp notification the supervisor has received, since the listener waits
// killable (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV): an ask held for a person, or a held read whose open deputy is
// in the frozen cgroup with the agent.
const FreezeWait = time.Second

// ErrNotFrozen is a freeze or a thaw that cgroup.events did not confirm within FreezeWait.
var ErrNotFrozen = errors.New("cgroup: the freezer did not reach the asked state in time")

// Freeze writes cgroup.freeze of c, "1" when on and "0" otherwise, with the one control-file writer every other
// write of this package uses (resolved against the scope's descriptor while it is open). It is the run's own cgroup
// only: c is the Cgroup Create made for the run. A frozen task does not run, so it neither progresses nor handles a
// signal; a fatal signal (SIGKILL, cgroup.kill) still ends it (Documentation/admin-guide/cgroup-v2.rst, "Core
// Interface Files"). A missing file (a kernel before 5.2, or the scope already gone) says so.
func Freeze(c Cgroup, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := writeControl(c, fileFreeze, v); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("cgroup: %s: no cgroup.freeze (the scope is gone, or the kernel predates 5.2): %w", c.Path, err)
		}
		return fmt.Errorf("cgroup: freeze %s: %w", c.Path, err)
	}
	return nil
}

// Frozen reads the frozen flag of c's cgroup.events: whether every task of c and of its descendants is frozen.
func Frozen(c Cgroup) (bool, error) {
	data, err := readControl(c, fileEvents)
	if err != nil {
		return false, err
	}
	n, ok := parseCounter(data, "frozen")
	if !ok {
		return false, fmt.Errorf("cgroup: %s: no frozen line", filepath.Join(c.Path, fileEvents))
	}
	return n != 0, nil
}

// WaitFrozenWithin returns once c's cgroup.events says frozen as on asks, waking on inotify and re-reading at least every
// pollFallback; it waits at most d, then answers ErrNotFrozen. ctx bounds it too. A caller that makes several short
// attempts at a freeze (internal/runtime's pause) waits on each for a fraction of the whole.
func WaitFrozenWithin(ctx context.Context, c Cgroup, on bool, d time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	if frozen, err := Frozen(c); err != nil || frozen == on {
		return err
	}
	w := newWatcher(filepath.Join(c.Path, fileEvents))
	defer w.close()
	for {
		frozen, err := Frozen(c)
		if err != nil {
			return err
		}
		if frozen == on {
			return nil
		}
		if err := w.wait(ctx); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("%w: %s frozen %t after %s", ErrNotFrozen, c.Path, frozen, d)
			}
			return fmt.Errorf("cgroup: wait frozen %s: %w", c.Path, err)
		}
	}
}
