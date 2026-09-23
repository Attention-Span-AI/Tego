// SPDX-License-Identifier: Apache-2.0

package bpf

// Regenerate the bindings after editing anything under /bpf:
//
//	make gen    # the pinned toolchain, scripts/bpf-toolchain.sh; the only output CI's bpf-gen accepts
//
// Each line compiles one C object with clang (dev-time only) and embeds it as a CO-RE object; users of the
// binary never need clang or headers. The generated *_bpfel.go/*_bpfeb.go files and their .o objects are
// committed, as bpf2go projects do, so `go build -tags tegobpf` works on a machine with no clang; CI
// regenerates them with the pinned clang and fails on any difference (bpf/README.md, .github/workflows/ci.yml
// job bpf-gen). A build without the tag compiles and tests everything else (see objects.go).
//
// Toolchain (bpf/README.md records the exact versions): clang from a user-local LLVM release, the libbpf
// headers vendored under bpf/include/libbpf, and bpf/include/vmlinux.h generated from the host's BTF.
//
// Targets. Three objects are architecture-neutral and are compiled once per byte order (bpfel, bpfeb). The
// uprobe object is not: PT_REGS_PARM*/PT_REGS_RC read a probed function's arguments out of struct pt_regs,
// whose layout is per architecture, and libbpf's bpf_tracing.h refuses them at compile time unless
// __TARGET_ARCH_<arch> says which. bpf2go defines that macro only for an architecture target, so uprobessl is
// compiled for the two architectures a release ships (.goreleaser.yaml goarch: amd64, arm64), which is also
// why objects_ssl_*.go register it only there. TestUprobeObjectsNameAnArchitecture pins the rule.
//
// The -type flags are what keeps the Go and C layouts from drifting: each one emits a Go mirror of a C struct
// whose size and field offsets are asserted against this package's own hand-written mirrors in types.go
// (parity_tegobpf_test.go), so a field added to bpf/include/events.h without a Go counterpart fails the
// test. bpf2go looks a -type name up among every BTF type of the object, maps included, so no map may share
// its name with a struct (bpf/tests TestNoMapNamedLikeAStruct).

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb -type tego_ev_sock -type tego_ev_sockopt -type tego_net_owner cgroupnet ../../bpf/cgroup_net.bpf.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb -type tego_hdr -type tego_ev_cgroup cgrouptrack ../../bpf/cgroup_track.bpf.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb -type tego_hdr -type tego_ev_exec -type tego_ev_exec_result -type tego_ev_exit -type tego_ev_fs -type tego_ev_fsop -type tego_ev_net -type tego_ev_bind_result trace ../../bpf/trace_proc.bpf.c -- -I../../bpf/include
// trace_proc is compiled twice as well, once per reader of kernel memory (ADR 0024's 2026-09-29 tier-2 note): trace
// reads through CO-RE bpf_probe_read_kernel, and tracerd (TEGO_TRACE_RDONLY=1) by direct BTF loads and
// bpf_rdonly_cast with no bpf_probe_read_kernel* call, the only one lockdown=confidentiality lets load. Both are one
// tier-2 object, ObjectTraceProc; TraceObject picks the build by the kernel's BTF. tracerd emits no -type: its
// records are trace's C structs, and TestReaderBuildsAreOneObject holds its programs and maps to trace's.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -DTEGO_TRACE_RDONLY=1" -target bpfel,bpfeb tracerd ../../bpf/trace_proc.bpf.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 -type tego_hdr -type tego_ev_ssl_chunk -type tego_ev_ssl_close -type tego_ssl_key -type tego_ssl_scratch uprobessl ../../bpf/uprobe_ssl.bpf.c -- -I../../bpf/include

// Tier 3's decision plane (bpf/decide.bpf.c, ADRs 0024, 0025) is compiled twice per byte order, once per reader
// of the walk: planerd reads through bpf_rdonly_cast and planepr through CO-RE probe reads. A kernel without the
// kfunc refuses planerd outright, and lockdown=confidentiality refuses planepr's helper, so the plane probe picks
// one by the kernel's BTF (ADR 0024's T0 note). Both are registered apart from the tier-2 objects
// (objects_plane_gen.go): no tier-2 load iterates them.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -DTEGO_PLANE_RDONLY=1" -target bpfel,bpfeb -type tego_plane_row -type tego_plane_exec_row -type tego_plane_decision -type tego_plane_counts -type tego_ev_plane -type tego_plane_unix -type tego_plane_slot -type tego_plane_bind -type tego_plane_listen_key -type tego_plane_listen_row -type tego_plane_name_row -type tego_plane_name_cfg -type tego_exec_pin -type tego_pin_key -type tego_pin_keyval -type tego_exec_armed -type tego_ev_exec_kill -type tego_ev_exec_held planerd ../../bpf/decide.bpf.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -DTEGO_PLANE_RDONLY=0" -target bpfel,bpfeb planepr ../../bpf/decide.bpf.c -- -I../../bpf/include

// The plane's fill and clear (bpf/decide_fill.bpf.c, ADR 0025 (2); TIER3-PLAN T4): an iter/task_file program that
// writes a slot's rows at the inodes of the launcher's held descriptors, and a syscall program that deletes a slot's
// stale rows. Built twice for the same reason as the plane (the mount id is read through a cast), and registered
// apart from both the tier-2 objects and the plane builds (objects_planefill_gen.go).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -DTEGO_PLANE_RDONLY=1" -target bpfel,bpfeb -type tego_plane_fill_cfg -type tego_plane_fill_row -type tego_plane_clear_ctx planefillrd ../../bpf/decide_fill.bpf.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -DTEGO_PLANE_RDONLY=0" -target bpfel,bpfeb planefillpr ../../bpf/decide_fill.bpf.c -- -I../../bpf/include

// The plane's root tests fill rows keyed by inode pointers from a test's own descriptors, without T4's
// fdinfo-checked Prepare, through a test-only iter/task_file program (bpf/testonly/plane_fill.bpf.c). Its binding builds with -tags integration,tegobpf only,
// so no tego binary embeds it.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb -tags integration,tegobpf -type tego_test_fill_tmpl -type tego_test_fill_cfg planetestfill ../../bpf/testonly/plane_fill.bpf.c -- -I../../bpf/include

// ADR 0048 P2's K0 probe (bpf/testonly/exec_pin_facts.bpf.c): the kernel facts exec pins rest on, measured on each
// matrix row by exec_pin_facts_integration_test.go. Built once per reader as the plane is, with -tags
// integration,tegobpf only, so no tego binary embeds it and tools/adoptiongen leaves it out.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -DTEGO_PLANE_RDONLY=1" -target bpfel,bpfeb -tags integration,tegobpf -type tego_pf_cfg -type tego_pf_exec -type tego_pf_stage -type tego_pf_counts -type tego_pf_sip_ctx pinfactsrd ../../bpf/testonly/exec_pin_facts.bpf.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -DTEGO_PLANE_RDONLY=0" -target bpfel,bpfeb -tags integration,tegobpf pinfactspr ../../bpf/testonly/exec_pin_facts.bpf.c -- -I../../bpf/include

// The adoption metadata follows the compiled objects and is bound to their exact
// bytes. It avoids parsing instructions/BTF for a fully reusable pinned build.
//go:generate go run ../../tools/adoptiongen -dir . -output adoption_specs_gen.go
