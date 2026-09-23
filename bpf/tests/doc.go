// SPDX-License-Identifier: Apache-2.0

// Package bpftests holds the userspace checks over the C sources under bpf/ that need neither clang nor a
// kernel: the static invariants docs/p0/enforce-cgroup-observe.md §8 says are "checked by a static grep over
// bpf/*.bpf.c" (I1, I3, I9) plus the licence and header conventions of §9 and bpf/README.md.
//
// They run in every build, including CI runners without an LLVM toolchain, and they fail loudly when someone
// adds a hook that walks ancestors, a cgroup program that returns something other than 0 or 1, a bpf_d_path
// call from a program the kernel's btf_allowlist_d_path excludes, or a file without the dual licence the
// kernel requires before it will run a GPL-only helper.
//
// Map-logic tests (prefix match, host match, verdict precedence) live with the code that builds the keys, in
// internal/bpf; this package only reads the C.
package bpftests
