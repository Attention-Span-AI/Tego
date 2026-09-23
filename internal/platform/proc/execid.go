// SPDX-License-Identifier: Apache-2.0

package proc

import "github.com/attention-span-ai/tego/pkg/spec/identity"

// ExecStartNS is the start time an exec id carries: startBootNS rounded down to a whole USER_HZ tick.
//
// Two producers name the same process. The seccomp supervisor reads the start from /proc/<pid>/stat, which
// the kernel already rounds down to a tick (nsec_to_clock_t on task->start_boottime). The tier-2 recorder
// has the exact task->start_boottime from its BPF program. Formatted as they come, one process got two exec
// ids, and a parent_exec_id written by one producer never matched an exec_id written by the other. Rounding
// the exact value the way the kernel rounds it for /proc makes the two equal by construction. Uniqueness
// is not lost: two processes share a (pid, tick) only if the pid space wraps within one 10 ms tick.
func ExecStartNS(startBootNS uint64) uint64 { return startBootNS - startBootNS%NanosPerTick }

// ExecID is the exec id (spec/identity/RUN-IDENTITY.md) of process pid of run, started startBootNS
// nanoseconds after boot at whatever precision the caller has: a /proc-derived start and an exact kernel
// start of the same process yield the same id (ExecStartNS). Every producer of exec_id and parent_exec_id
// builds it here and nowhere else.
func ExecID(run identity.RunID, pid int, startBootNS uint64) identity.ExecID {
	return identity.NewExecID(run, pid, ExecStartNS(startBootNS))
}
