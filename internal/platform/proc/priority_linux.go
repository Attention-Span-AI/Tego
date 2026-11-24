// SPDX-License-Identifier: Apache-2.0

//go:build linux

package proc

import "golang.org/x/sys/unix"

// lowestNice is the lowest scheduling priority nice(2) gives; lowering needs no privilege, raising does.
const lowestNice = 19

// LowerPriority gives the calling OS thread the lowest CPU priority the system allows an unprivileged process: nice
// 19, and the idle scheduling policy (SCHED_IDLE) where the kernel permits it, so the thread runs only while no
// normal thread wants the CPU. idle says whether the policy took; nice 19 is always set or the call fails. Both
// settings belong to the thread, and a process Start forks from it takes them (a child inherits the policy and
// the nice value of the thread that forked it, and every thread of the child descends from its first), so a
// program that lowers its own start thread first, and then starts a child with Start, starts that child at low
// priority from its first instruction and everything it starts after it. The caller holds its OS thread
// (runtime.LockOSThread) from this call through Start. Priority is never raised: an unprivileged process
// cannot, and no function here tries to.
func LowerPriority() (idle bool, err error) {
	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, lowestNice); err != nil {
		return false, err
	}
	attr := unix.SchedAttr{Size: unix.SizeofSchedAttr, Policy: unix.SCHED_IDLE}
	return unix.SchedSetAttr(0, &attr, 0) == nil, nil
}
