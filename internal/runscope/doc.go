// SPDX-License-Identifier: Apache-2.0

// Package runscope is the one rule for run membership: whether a cgroup path is a tego run's, read from the path
// alone, and whether the calling process is outside every run. The path has two answers, kept apart on purpose
// (ADR 0100 (7)).
//
// GovernedBy is the strict answer: the run a path names, read only where tego makes a run's cgroup (and
// AdoptionScopeRun, exactly an adoption's scope). It is what may name a run, and so what anything that acts on a run
// (adopt's release, the watcher's governance column) reads. A run's name anywhere else is anyone's to make and names
// no run (ADR 0055, "The scope guard").
//
// LooksGoverned is the broad answer, for refusals only: true for every path GovernedBy names a run in and for every
// look-alike of one, wherever it sits. A socket that serves the person and never a run (ask.sock)
// refuses a peer whose cgroup LooksGoverned; nothing reads a run id from it or
// acts on a run because of it, so a look-alike costs its maker a refusal and gains nothing.
//
// Decide is the rule for the calling process itself (rule.go), with three answers (Answer: Inside, the zero value;
// Unknown, always with a typed Cause; Outside). Only Outside permits a governance change, an approval or the entry
// into a user scope, and Answer.Outside is the one way a caller reads it. The claim of Outside is "in no run's
// cgroup made inside this process's own cgroup namespace": in the kernel's first cgroup namespace (InitCgroupNS)
// that is LooksGoverned of the process's own path and nothing more; in any other namespace the path starts at the
// namespace's root, a run's scope above that root cannot show, and Outside needs the proof Prove describes (the
// namespace is owned by the first user namespace, pid 1 is in /init.scope, and the user's own service manager
// answers from its exact cgroup). The answer is computed in the process it describes: it is the refusal an honest
// tego gives, not a boundary against a process that controls the tego it starts. Decide and Prove are pure over the
// reads they are handed (Facts, Prober); the kernel's reads, the proof's cache and its time limit are
// internal/platform/peer's (peer.Self).
//
// Unified is the strict reader of a /proc/<pid>/cgroup file all of them use: exactly one cgroup v2 ("0::") line,
// with an absolute path, or an error. OutsideNamespace says a path read so lies above the reader's cgroup namespace
// root. FdinfoPid reads the Pid: line of a pidfd's fdinfo.
//
// It is a leaf of Layer 1: pure functions over strings, bytes and injected reads. No state, no goroutines, no
// clock, no system call.
//
// Imports: standard library, pkg/spec/identity (depguard runscope-is-a-leaf; TestImportsOnlyTheLeafSet)
package runscope
