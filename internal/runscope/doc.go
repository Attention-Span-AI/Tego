// SPDX-License-Identifier: Apache-2.0

// Package runscope is the one rule for run membership: whether a cgroup path is a tego run's, read from the path
// alone. It has two answers, kept apart on purpose (ADR 0100 (7)).
//
// GovernedBy is the strict answer: the run a path names, read only where tego makes a run's cgroup (and
// AdoptionScopeRun, exactly an adoption's scope). It is what may name a run, and so what anything that acts on a run
// (adopt's release, the watcher's governance column) reads. A run's name anywhere else is anyone's to make and names
// no run (ADR 0055, "The scope guard").
//
// LooksGoverned is the broad answer, for refusals only: true for every path GovernedBy names a run in and for every
// look-alike of one, wherever it sits. A socket that serves the person and never a run (ask.sock)
// refuses a peer whose cgroup LooksGoverned; nothing reads a run id from it or
// acts on a run because of it, so a look-alike costs its maker a refusal and gains nothing. InRun is LooksGoverned of
// this process's own cgroup, failing closed: a service that must not start inside a run asks it. Outside the initial
// cgroup namespace (InitCgroupNS) it is always true, with the error: a namespace's members read their cgroups from its
// root, so a run's scope above that root cannot show, and a cgroupns-private container cannot be told from an agent
// that unshared a namespace inside its run.
//
// Unified is the strict reader of a /proc/<pid>/cgroup file both use: exactly one cgroup v2 ("0::") line, with an
// absolute path, or an error. OutsideNamespace says a path read so lies above the reader's cgroup namespace root.
//
// It is a leaf of Layer 1: pure functions over strings and bytes, and InRun's reads of /proc/self/cgroup and
// /proc/self/ns/cgroup. No state, no goroutines, no clock.
//
// Imports: standard library, pkg/spec/identity (depguard runscope-is-a-leaf; TestImportsOnlyTheLeafSet)
package runscope
