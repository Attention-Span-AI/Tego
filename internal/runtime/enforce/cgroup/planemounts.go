// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The plane's mounted-root rows (docs/p0/enforce-plane.md R12; ADR 0024 (5)): the attribute hooks get a dentry and
// no mount, so their walk stays inside one superblock, and Prepare keys a row on every mounted root at or below a
// deny_write target so that walk meets one (decide.PlaneRows.WithMounts). The mountpoints are the launcher's: the
// agent runs in the launcher's mount namespace, and neither can mount (enforce-landlock R11, the filter's mount arm).

// mountInfoPath is the launcher's mount table; a variable so a test can hand MountPoints a table of its own.
var mountInfoPath = "/proc/self/mountinfo"

// ErrMountTable is a launcher whose mount table cannot be read. The plane cannot key the mounted roots below a
// deny_write target (enforce-plane R12), so it cannot hold a table that names one: tier cgroup runs such a table on
// the fanotify listener, saying why; tier bpflsm refuses it (ErrPlaneCannotHold). The listener cannot mark the mount
// points beneath a deny_read entry (enforce-cgroup-observe R8), so Prepare refuses a table that has one. Either way
// never a run quieter than its contract (I7).
var ErrMountTable = errors.New("the mount table cannot be read")

// MountPoints lists the mountpoints of this process's mount namespace, as /proc/self/mountinfo prints them
// (resolved, absolute), or ErrMountTable when the table cannot be read: keying no mount row would let an attribute
// change on a filesystem mounted below a deny_write target walk to that filesystem's root and pass. The table is
// read by agent.MountPoints, the one mountinfo parser: fields split on spaces alone, since a mount point may hold
// \v, \r or U+00A0 unescaped.
func MountPoints() ([]string, error) {
	b, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("%w, so the plane cannot key the mounted roots below a deny_write target: %w", ErrMountTable, err)
	}
	return agent.MountPoints(b), nil
}

// IOUringDecided reports whether a run of this tier whose opens, execs, fs mutations and sockets a plane mode
// decides also has every other io_uring submission decided in the kernel, so that the inherited filter may admit
// io_uring_* for a contract that declares io_uring: true (ADR 0018 (5), ADR 0024 step B): the plane's socket_create
// decides io_uring's IORING_OP_SOCKET, its path and file hooks the fs ops, cgroup/connect4, 6 and sendmsg4, 6 the
// inet sends, and a unix name cgroup/connect_unix and sendmsg_unix decide on 6.7+ and the plane's step D hooks
// (socket_connect, socket_sendmsg; TIER3-PLAN T15) below. It holds wherever a plane mode runs; the caller asks it
// only then (Run.PlaneRows set). A variable so the selection's tests can give both answers.
var IOUringDecided = func() bool { return true }
