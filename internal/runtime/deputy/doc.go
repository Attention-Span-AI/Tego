// SPDX-License-Identifier: Apache-2.0

// Package deputy is the run's open deputy (ADR 0041 D2, Stage B): a tego process that belongs to the run, with
// the run's Landlock domain, cgroup, credentials, namespaces and LSM label, which walks and opens files for the
// supervisor so that a held open is performed in the run's own kernel context rather than in the launcher's.
//
// The child stage starts it (launch, `tego __open-deputy`) after landlock_restrict_self and inside the run cgroup,
// before it installs the run's listener filter, so the deputy carries the run's domain and no notification of its
// own. The deputy sets PR_SET_DUMPABLE 0, so the agent cannot ptrace it or reach its descriptors through /proc, arms
// PR_SET_PDEATHSIG against the launcher, sets no_new_privs and installs an allowlist seccomp filter (Filter) that
// kills it on any syscall outside walking, opening, stating, reading links, setting the umask, the socket protocol,
// exit and what the Go runtime needs to run threads. A read of any descriptor but the runtime poller's eventfd is
// refused EPERM rather than fatal: the deputy reads no file, and a cgo build's libc probes one on a new thread (the
// CPU count glibc's malloc reads). It then talks only over the socketpair the launcher made: a
// hello carrying its pid, which the launcher reads with kernel-attested credentials (SCM_CREDENTIALS), then one
// request socket per concurrent caller, each passed to it over the control socket (SCM_RIGHTS).
//
// Two requests exist. Pin walks a pathname as the trapping task's own lookup walks it (the supervisor's walk, from
// /proc/<tid>/root and its cwd or dirfd) and returns an O_PATH descriptor of what it reached, or of the directory an
// O_CREAT open would create its final component in, with that component's name. Open opens with the task's flags:
// the pinned object reopened through /proc/self/fd, or the missing leaf created beneath its pinned parent under the
// task's umask, set with umask(2) under a deputy-wide lock since the deputy's threads share one fs_struct (D5). Every
// open is the kernel's own, made by a process of the run: Landlock, the decision plane, fanotify and DAC decide it as
// they decide the agent's, and the descriptor carries the domain's TRUNCATE and IOCTL_DEV rights. The supervisor
// checks and scores what the deputy pinned before it asks for the open, verifies the opened descriptor is the pinned
// inode, and delivers it with ADDFD|SEND (D3).
//
// The deputy never decides anything. Its walk and its opens are the only work it does, and an error is an errno the
// supervisor maps onto the agent's answer or a fail-closed refusal (D4).
package deputy
