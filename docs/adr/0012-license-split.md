# ADR 0012: Apache-2.0, with `bpf/` dual GPL-2.0-only OR BSD-2-Clause

Status: accepted 2026-09-21.
Decision: root `LICENSE` is Apache-2.0 for everything except `bpf/`, which is dual `GPL-2.0-only OR BSD-2-Clause`; every `.bpf.c` defines `char _license[] SEC("license") = "Dual BSD/GPL";` and starts with the matching SPDX header. SPDX header on every source file, checked in CI; `bpf/include/vmlinux.h` and bpf2go output exempt; DCO sign-off in CONTRIBUTING.
Why: `kernel/bpf/bpf_lsm.c` refuses non-GPL-compatible LSM programs at load, and kfuncs and `bpf_probe_read_*` are GPL-only; the BSD option lets bpf2go embed the objects and generated types in the Apache-2.0 binary, as Tetragon and Cilium do.
Consequence: decided before the first `.bpf.c`; `internal/bpf/doc.go` states the derivation; the licence line is in the README.

*Amended 2026-10-05:* the dual licence covers the kernel programs and headers under `bpf/`; the Go map-logic tests under `bpf/tests` are Apache-2.0, as they have been since they were added, and are not part of any kernel object.

*Amended 2026-11-01:* "headers" above means the headers written for the kernel programs. Two files under `bpf/include/` keep other terms: `vmlinux.h`, generated from the kernel's own type information, is GPL-2.0-only, and the vendored `libbpf/` headers are LGPL-2.1 OR BSD-2-Clause. The objects in `internal/bpf/` and the Go files bpf2go generates carry the terms of `bpf/`. The position on the objects: each is a separate program that a Go binary carries as data and loads into the kernel, so the binary and the objects are an aggregate, with no GPL code linked into Go. The objects keep the BTF of the kernel types they use, which is names and layouts, the interface information a program needs to run against that kernel. The corresponding source is in `bpf/`, and the GPL option stays open to anyone who takes an object on its own.
