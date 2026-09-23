// SPDX-License-Identifier: Apache-2.0

// Package proc reads /proc: the process cache the kernel record enriches its events from (exec id,
// parent, binary, argv, cwd, comm), the cgroup a pid belongs to, and the libraries a process has
// mapped (how capture/uprobe finds the libssl a process uses). It is also where every process start of
// non-test code happens (Start, ADR 0021 (3)): refused while this process is armed (Arm, a fanotify
// group of its own holding marks), and returning the started process's Identity, its pid and start
// time, which is how a pid kept across time is told from a reused one (SameProcess).
// Lint allows os/exec, os.StartProcess, syscall.ForkExec and the fork and clone syscalls in this
// package only. A call of Start, or of cgroup.StartHelper, the helper starter built on it, is a reviewed
// site (ADR 0021 (6)): .golangci.yml names its file and sites_test.go its function, with when its start
// runs against Arm. So is a call of an unexported function that makes one of them, which only sites_test.go
// can name.
//
// Every parser here is a pure function over bytes the kernel supplied, kept separate from the file
// access so it can be fuzzed without /proc (docs/ARCHITECTURE.md §7, §16: every reader of foreign
// bytes has a fuzz target). Nothing in this package keeps a goroutine or holds an fd past a call;
// nothing blocks but Start's fork and Arm's wait for a start in flight; and no function panics on
// malformed input: a short, truncated or re-raced file is an error, never a crash. A pid that disappears mid-read is ErrGone, the expected outcome of racing a process
// that exited (docs/p0/enforce-cgroup-observe.md §7 "/proc read races an exited pid").
//
// ExecID is the one constructor of an exec id for every producer (the seccomp supervisor from /proc, the
// tier-2 recorder from the kernel's exact start), so both name one process the same way.
//
// Imports: standard library (os/exec for Start), pkg/spec/identity (the exec id type)
// Must not import: cilium/ebpf
package proc
