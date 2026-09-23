// SPDX-License-Identifier: Apache-2.0

// Package sys wraps the Linux syscalls the child stage and the launcher need that golang.org/x/sys/unix
// does not cover, or covers without the argument naming the trusted computing base wants in its errors:
// pidfd_open/pidfd_getfd/pidfd_send_signal and waitid(P_PIDFD); the prctl(2) options PR_SET_CHILD_SUBREAPER,
// PR_SET_PDEATHSIG, PR_SET_NO_NEW_PRIVS and PR_SET_DUMPABLE with their getters; capset(2) to the empty set plus
// PR_CAP_AMBIENT_CLEAR_ALL, on the calling thread or, through syscall.AllThreadsSyscall, on every thread
// (ClearProcessCapabilities); the ambient set read by PR_CAP_AMBIENT_IS_SET; the raw landlock_create_ruleset/landlock_add_rule/landlock_restrict_self calls and
// the ABI probe; seccomp(2) SET_MODE_FILTER with NEW_LISTENER returning the listener fd, the user-notification
// ioctls (RECV, SEND, ID_VALID, SET_FLAGS) with the kernel's struct layouts, and GET_NOTIF_SIZES; uname(2) with
// a release parser; the terminal test on a file descriptor; and a task's credentials read from
// /proc/<tid>/status, with RunAs, which runs one call on a thread that has taken them.
//
// RunAs is the exception to the rule below: it is several syscalls and a thread of its own, because
// credentials are per thread in Linux and the supervisor needs one relayed unix connect judged as the
// agent's (docs/p0/supervisor.md R11). The thread takes the credentials with raw setgroups/setresgid/
// setresuid, which change the calling thread only, reads them back before running anything, and is never
// returned to the Go scheduler; the process's own credentials never change.
//
// Every wrapper does one job its name states, returns the errno wrapped with the syscall name and the
// argument that mattered, and carries nothing between calls. Most are one syscall, restarted on EINTR where
// the call can block. The few that make a second one say so where they are declared, each for one of three
// reasons:
//
//   - a retry without a flag the running kernel does not know (PidfdOpenThread, PidfdSendSignal);
//   - a precondition whose absence the operation would otherwise report far from here: PollPidfd and
//     WaitPidfd read the pidfd's scope, SeccompSetFilterNewListener the kernel's notification layout, both
//     for the reasons below;
//   - a postcondition the first syscall reaches only as a kernel side effect, stated outright so it does
//     not rest on that side effect (ClearCapabilities: capset to empty permitted and inheritable sets
//     already empties the ambient set, because the kernel keeps ambient within permitted ∩ inheritable;
//     PR_CAP_AMBIENT_CLEAR_ALL then clears it by name).
//
// The retries keep those wrappers working on 5.14–6.8: without them every call there fails EINVAL and the
// wrapper returns that error, so dropping one is loud, not silent (TestKernelWithoutPidfdThread runs this
// package's pidfd tests under an emulation of those kernels' flag answers). The silent failures are the ones
// the two scope rules below describe. The precondition checks guard them, as does the flag PidfdSendSignal's
// first call carries: flags 0 alone would signal one task through a thread-scoped fd on 6.9+, with no error
// at all. The third kind is redundant on every kernel that has ambient capabilities and is kept because it
// costs one syscall once per run and makes the child stage's empty-ambient guarantee explicit rather than
// inferred.
//
// FD is the owned descriptor of ADR 0023 (as amended 2026-10-05): one close-once owner per number, lent only
// through a counted lease (Borrow, Hold) whose Close is deferred to the last Return, given away only through
// Release or ReleaseNumber, forgotten without a close only through Abandon, and never closed by the garbage
// collector. It is born where its number is (Own, OwnSyscall, Adopt, Inherited, Stdio); fd.go, fd_lease.go,
// fd_errors.go and fd_inherited.go hold it, fd_testhooks.go its tegotesthooks checks. Callers move to it
// package by package (ADR 0023's C5–C19), and the lint of its C3 holds the rest of the tree to it.
//
// Nothing here decides policy; the ordering of these calls is the child stage's.
//
// Two scope rules this package enforces rather than documents, because both failures are silent:
//
//   - A pidfd carries its scope. PIDFD_THREAD (PidfdOpenThread) names one task: pidfd_send_signal on it
//     with flags 0 is thread-directed and it becomes readable when that task alone is a zombie.
//     PidfdOpenProcess names the thread group. PidfdSendSignal therefore states PIDFD_SIGNAL_THREAD_GROUP
//     explicitly whatever it is handed, and PollPidfd/WaitPidfd refuse a thread-scoped fd
//     (ErrThreadScopedPidfd) rather than report one thread's exit as the whole process's.
//   - A listener is never created for a kernel whose notification structs differ from this build's.
//     SeccompSetFilterNewListener checks GET_NOTIF_SIZES first (ErrSeccompNotifLayout), because the struct
//     size is part of the RECV ioctl number and a mismatch would otherwise surface only once the agent was
//     already running.
//
// Imports: golang.org/x/sys/unix, golang.org/x/net/bpf
// Must not import: anything above runtime
package sys
