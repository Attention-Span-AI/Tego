// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// kernelWith is a kernel BTF holding a static function of each name.
func kernelWith(t *testing.T, funcs ...string) *btf.Spec {
	t.Helper()
	var types []btf.Type
	for _, name := range funcs {
		types = append(types, &btf.Func{Name: name, Type: &btf.FuncProto{Return: (*btf.Void)(nil)}, Linkage: btf.StaticFunc})
	}
	b, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := b.Spec()
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestChooseReader is the plane's rule for tier 2's trace_proc (ADR 0024 (9) and its tier-2 note): the rdonly build
// where the kernel's BTF has bpf_rdonly_cast and bpf_loop, whatever the lockdown; the probe build elsewhere, which
// under lockdown=confidentiality is a build that cannot load, and Loadable says so.
func TestChooseReader(t *testing.T) {
	const conf = "none integrity [confidentiality]"
	cases := []struct {
		name     string
		kernel   *btf.Spec
		lockdown string
		want     Reader
		loadable bool
		why      string
	}{
		{"6.17", kernelWith(t, "bpf_rdonly_cast", "bpf_loop"), "[none] integrity confidentiality", ReaderRdonly, true, "has bpf_rdonly_cast and bpf_loop"},
		{"6.17 confidentiality", kernelWith(t, "bpf_rdonly_cast", "bpf_loop"), conf, ReaderRdonly, true, "has bpf_rdonly_cast"},
		{"6.1", kernelWith(t, "bpf_loop"), "", ReaderProbe, true, "no bpf_rdonly_cast"},
		{"6.1 confidentiality", kernelWith(t, "bpf_loop"), conf, ReaderProbe, false, "no bpf_rdonly_cast"},
		{"5.15", kernelWith(t, "bpf_rdonly_cast"), "", ReaderProbe, true, "no bpf_loop"},
		{"no BTF", nil, conf, ReaderProbe, false, "BTF is unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ChooseReader(tc.kernel, tc.lockdown)
			if got.Reader != tc.want || got.Loadable() != tc.loadable || !strings.Contains(got.Why, tc.why) {
				t.Fatalf("ChooseReader = %+v (loadable %v), want %s, loadable %v, why containing %q", got,
					got.Loadable(), tc.want, tc.loadable, tc.why)
			}
		})
	}
}

// TestReadersOfAnUntaggedBuild: without the objects nothing is compiled per reader, and LoadReader reports
// ErrNotGenerated like Load; with them, trace_proc is.
func TestReadersOfAnUntaggedBuild(t *testing.T) {
	if Available() {
		if !HasReaders(ObjectTraceProc) {
			t.Fatal("a build with the objects has no rdonly build of trace_proc")
		}
		return
	}
	if HasReaders(ObjectTraceProc) {
		t.Fatal("an untagged build has an rdonly build")
	}
	if _, err := LoadReader(ObjectTraceProc, ReaderRdonly); err == nil {
		t.Fatal("LoadReader succeeded without the objects")
	}
}

// TestProbeReadKernelIsTakenAsPresent: cilium/ebpf loads bpf_probe_read_user as written, not as the legacy
// bpf_probe_read lockdown refuses (proberead.go). A rename of the library's variable fails the link instead.
func TestProbeReadKernelIsTakenAsPresent(t *testing.T) {
	if !probeReadKernelFixed() {
		t.Fatal("cilium/ebpf's bpf_probe_read_kernel feature test is not fixed to present")
	}
}
