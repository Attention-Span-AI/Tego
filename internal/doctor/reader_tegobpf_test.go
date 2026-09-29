// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package doctor

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// TestLockdownRowIsRefusedBeforeAnyLoad: a trace_proc row on a kernel where no build loads (lockdown=confidentiality
// and no bpf_rdonly_cast) is answered with the cause and loads nothing; on a kernel with the rdonly build the row
// names it.
func TestLockdownRowIsRefusedBeforeAnyLoad(t *testing.T) {
	saved := kernelReader
	t.Cleanup(func() { kernelReader = saved })
	h := hookNamed(t, "fexit/security_file_open")
	loads := 0
	counting := func(o bpfobj.Object) (*ebpf.CollectionSpec, error) {
		loads++
		return &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}, Maps: map[string]*ebpf.MapSpec{}}, nil
	}

	kernelReader = func() bpfobj.ReaderChoice {
		return bpfobj.ReaderChoice{Reader: bpfobj.ReaderProbe, Why: "the kernel's BTF has no bpf_rdonly_cast", Confidentiality: true}
	}
	got := testHookWith(h, nil, nil, nil, Version{6, 1, 0}, counting)
	if loads != 0 || !got.Lockdown || got.Loaded || got.Reader != "probe" ||
		!strings.Contains(got.Detail, "lockdown=confidentiality refuses bpf_probe_read_kernel") {
		t.Fatalf("row under confidentiality without the rdonly build = %+v after %d loads", got, loads)
	}

	kernelReader = func() bpfobj.ReaderChoice {
		return bpfobj.ReaderChoice{Reader: bpfobj.ReaderRdonly, Why: "the kernel's BTF has bpf_rdonly_cast and bpf_loop", Confidentiality: true}
	}
	got = testHookWith(h, nil, nil, nil, Version{6, 17, 0}, counting)
	if got.Lockdown || got.Reader != "rdonly" {
		t.Fatalf("row with the rdonly build = %+v after %d loads", got, loads)
	}

	// cgroup_track has one build: no reader on its rows.
	got = testHookWith(hookNamed(t, "tp_btf/cgroup_mkdir"), nil, nil, nil, Version{6, 17, 0}, counting)
	if got.Reader != "" || got.Lockdown {
		t.Fatalf("cgroup_track's row = %+v, want no reader", got)
	}
}
