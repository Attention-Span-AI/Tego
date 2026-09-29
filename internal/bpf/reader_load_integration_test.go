// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// TestReaderBuildsLoadOnThisKernel loads each build of trace_proc this kernel can take, whole, the way
// TestObjectsLoadOnThisKernel loads the one Load picks (ADR 0024's tier-2 note): the rdonly build wherever the
// kernel's BTF has bpf_rdonly_cast and bpf_loop, lockdown or not, and the probe build wherever lockdown is not
// confidentiality. The build Load picks must be one of them.
func TestReaderBuildsLoadOnThisKernel(t *testing.T) {
	requireBPF(t)
	choice := KernelReader()
	t.Logf("this kernel takes the %s build: %s (confidentiality %v)", choice.Reader, choice.Why, choice.Confidentiality)
	if !choice.Loadable() {
		t.Fatalf("no build of %s loads here: %s under lockdown=confidentiality", ObjectTraceProc, choice.Why)
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("kernel BTF: %v", err)
	}
	for _, r := range Readers {
		t.Run(string(r), func(t *testing.T) {
			switch {
			case r == ReaderRdonly && choice.Reader != ReaderRdonly:
				t.Skip("this kernel's BTF lacks bpf_rdonly_cast or bpf_loop: " + choice.Why)
			case r == ReaderProbe && choice.Confidentiality:
				t.Skip("lockdown=confidentiality refuses bpf_probe_read_kernel")
			}
			spec, err := LoadReader(ObjectTraceProc, r)
			if err != nil {
				t.Fatal(err)
			}
			// What the backend leaves out where the kernel lacks the function (enforce/cgroup dropTraceWhereAbsent).
			for name, fn := range OptionalTracePrograms {
				var f *btf.Func
				if kernel.TypeByName(fn, &f) != nil {
					delete(spec.Programs, name)
				}
			}
			unpin(spec)
			start := time.Now()
			coll, err := ebpf.NewCollection(spec)
			if err != nil {
				t.Fatalf("load %s's %s build: %v", ObjectTraceProc, r, err)
			}
			defer coll.Close()
			t.Logf("%s build: %d programs loaded in %v", r, len(coll.Programs), time.Since(start))
		})
	}
}
