// SPDX-License-Identifier: Apache-2.0

// Package handoff is the engine's one way to reach tego-control, the control binary (ADR 0100 (1b)).
//
// Open finds tego-control beside the running tego, never on PATH or in the working directory, checks that it is a
// regular file owned by root or the caller with no group or world write, copies it into a sealed memfd, and
// compares the SHA-256 of the sealed copy with the hash the build pinned through -ldflags. What runs afterwards is
// that sealed copy: Exec replaces this process with it through syscall.Exec of its /proc/self/fd link (which also
// hands tego-control the soft RLIMIT_NOFILE tego started with), and Spawn starts it as a child. A write in place or a
// rename after Open cannot change what runs, and an unpinned build, a root caller or a kernel that refuses an
// executable memfd is refused with a reason code that maps to a pkg/spec/identity exit.
//
// Nouns is the list of commands tego hands to tego-control (ADR 0100 (2)): the engine registers a handoff for
// each, and tego-control registers a command for each, and a test holds the two lists equal.
//
// Imports: the standard library, golang.org/x/sys/unix, internal/platform/sys (descriptors, capabilities),
// internal/platform/proc (Spawn's one start) and pkg/spec/identity (exit codes).
// Must not import: the engine (internal/runtime, internal/policy, internal/bpf) or the dashboard
// (internal/control): both binaries link this package.
package handoff
