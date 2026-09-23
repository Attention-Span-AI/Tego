// SPDX-License-Identifier: Apache-2.0

// Package bpf holds the bpf2go-generated Go bindings for the C programs under /bpf and the shared map and
// event struct definitions; regenerate with go generate.
//
// The package has two halves. The always-compiled half — the map and program names, the Go mirrors of every
// struct in bpf/include/events.h, the key construction and LPM prefix arithmetic, and the record decoder —
// needs no object and is unit-tested in every build. The embedded objects are behind the `tegobpf` build tag.
// They are committed (gen.go), so the tag needs no clang: a build with it embeds them, while a plain
// `go build`/`go test` compiles and tests everything else and Load reports ErrNotGenerated. Callers therefore
// treat a missing object as a runtime condition, never as a compile error (internal/runtime/enforce/cgroup
// turns it into ErrProgramLoad with the fix in the message).
//
// Layout parity between the C structs and the Go mirrors is not assumed: bpf2go emits its own mirror of each
// struct from the object's BTF, and parity_tegobpf_test.go asserts size and field-offset equality against
// the hand-written ones, so a field added to bpf/include/events.h without a Go counterpart fails the tagged
// build rather than corrupting a decode.
//
// Normative sources: docs/p0/enforce-cgroup-observe.md §2 (structs), §3 (map sizing and pinning),
// docs/ARCHITECTURE.md §11 (portability rules), bpf/README.md (toolchain and versions).
//
// Imports: github.com/cilium/ebpf, standard library, and pkg/policy/socketpolicy (ADR 0018's socket allowlist,
// a standard-library-only leaf the decision core reads too, so the table has one Go spelling: SocketAllowed).
// Must not import: anything above runtime, any other internal package, pkg/spec.
// The embedded objects and generated types are produced by bpf2go from bpf/ and carry its licence,
// GPL-2.0-only OR BSD-2-Clause. The Go binary carries the objects as separate programs for the kernel,
// and the kernel type information they keep comes from bpf/include/vmlinux.h: NOTICE and ADR 0012 say
// where each of these stands.
package bpf
