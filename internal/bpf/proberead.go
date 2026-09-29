// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	_ "unsafe" // go:linkname

	_ "github.com/cilium/ebpf" // the package whose variable is named below, initialized before this one
)

// cilium/ebpf rewrites every bpf_probe_read_kernel and bpf_probe_read_user call (and their _str) to the legacy
// bpf_probe_read at load when its feature test for bpf_probe_read_kernel fails, a compatibility step for kernels
// below 5.5 (linker.go fixupProbeReadKernel). The test loads a program that calls bpf_probe_read_kernel, which
// lockdown=confidentiality refuses on every kernel, so under it the library decided the helper was missing and
// turned the user reads that lockdown allows — argv at exec, capture's TLS buffers — into bpf_probe_read, which
// lockdown refuses too: trace_proc's rdonly build and uprobe_ssl then failed to load with "cannot use helper
// bpf_probe_read#4" (ADR 0024's tier-2 note, measured on 6.17 in the KVM guest, 2026-09-29). Every kernel this
// project supports (5.14+) has bpf_probe_read_kernel, so the answer is fixed here: the helpers are loaded as
// written, and a kernel read lockdown refuses is refused under its own name.
//
//go:linkname haveProbeReadKernel github.com/cilium/ebpf.haveProbeReadKernel
var haveProbeReadKernel func() error

func init() {
	haveProbeReadKernel = func() error { return nil }
}
