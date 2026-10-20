// SPDX-License-Identifier: Apache-2.0

package bpf

// probeReadKernelFixed reports whether cilium/ebpf now takes bpf_probe_read_kernel as present, for the test that
// the variable named above is still the one the library reads.
func probeReadKernelFixed() bool { return haveProbeReadKernel != nil && haveProbeReadKernel() == nil }
