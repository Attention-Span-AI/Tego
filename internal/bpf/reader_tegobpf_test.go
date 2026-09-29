// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"maps"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// kernelProbeReads are the helpers lockdown=confidentiality refuses at load (LOCKDOWN_BPF_READ_KERNEL): the kernel
// reads and the legacy reads that may reach kernel memory. bpf_probe_read_user and its _str are not among them.
var kernelProbeReads = map[asm.BuiltinFunc]bool{
	asm.FnProbeRead:          true,
	asm.FnProbeReadStr:       true,
	asm.FnProbeReadKernel:    true,
	asm.FnProbeReadKernelStr: true,
}

// helperCalls returns every helper a spec's programs call, by program.
func helperCalls(spec *ebpf.CollectionSpec) map[string][]asm.BuiltinFunc {
	out := map[string][]asm.BuiltinFunc{}
	for name, p := range spec.Programs {
		for _, ins := range p.Instructions {
			if ins.IsBuiltinCall() {
				out[name] = append(out[name], asm.BuiltinFunc(ins.Constant))
			}
		}
	}
	return out
}

// kernelReadsOf lists "program: helper" for every kernel probe read a spec's programs make.
func kernelReadsOf(spec *ebpf.CollectionSpec) []string {
	var out []string
	for name, calls := range helperCalls(spec) {
		for _, fn := range calls {
			if kernelProbeReads[fn] {
				out = append(out, name+": "+fn.String())
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// TestNoProbeBuildsMakeNoKernelProbeRead is ADR 0024's tier-2 note: every build tier 2 loads under
// lockdown=confidentiality — trace_proc's rdonly build, cgroup_track and cgroup_net, which have one build — calls
// no helper that lockdown refuses. The probe build is checked to call one, so the test reads the calls it means to.
// uprobe_ssl reads user memory only, which lockdown does not refuse.
func TestNoProbeBuildsMakeNoKernelProbeRead(t *testing.T) {
	check := []struct {
		o Object
		r Reader
	}{{ObjectTraceProc, ReaderRdonly}, {ObjectCgroupTrack, ReaderRdonly}, {ObjectCgroupNet, ReaderRdonly}}
	if sslCompiledHere() {
		check = append(check, struct {
			o Object
			r Reader
		}{ObjectUprobeSSL, ReaderProbe})
	}
	for _, c := range check {
		spec, err := LoadReader(c.o, c.r)
		if err != nil {
			t.Fatalf("LoadReader(%s, %s): %v", c.o, c.r, err)
		}
		if got := kernelReadsOf(spec); len(got) > 0 {
			t.Errorf("%s (%s build) calls a helper lockdown=confidentiality refuses: %v", c.o, c.r, got)
		}
	}
	spec, err := LoadReader(ObjectTraceProc, ReaderProbe)
	if err != nil {
		t.Fatal(err)
	}
	if len(kernelReadsOf(spec)) == 0 {
		t.Fatalf("%s's probe build calls no bpf_probe_read_kernel: the helper list this test reads is wrong", ObjectTraceProc)
	}
}

// TestReaderBuildsAreOneObject holds trace_proc's two builds to one shape: the same programs with the same types
// and attach points, and the same maps with the same types, sizes and pinning, since the backend pins them under
// one build hash and adopts either's programs the same way. Only the probe build names the record types for
// bpf2go; the rdonly build's records are the same C structs, which this makes sure of through the maps they go to.
func TestReaderBuildsAreOneObject(t *testing.T) {
	if !HasReaders(ObjectTraceProc) || HasReaders(ObjectCgroupTrack) || HasReaders(ObjectCgroupNet) {
		t.Fatalf("readers: trace_proc %v, cgroup_track %v, cgroup_net %v; want only trace_proc compiled per reader",
			HasReaders(ObjectTraceProc), HasReaders(ObjectCgroupTrack), HasReaders(ObjectCgroupNet))
	}
	pr, err := LoadReader(ObjectTraceProc, ReaderProbe)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := LoadReader(ObjectTraceProc, ReaderRdonly)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := slices.Sorted(maps.Keys(pr.Programs)), slices.Sorted(maps.Keys(rd.Programs)); !slices.Equal(a, b) {
		t.Fatalf("programs differ: probe %v, rdonly %v", a, b)
	}
	for name, p := range pr.Programs {
		q := rd.Programs[name]
		if p.Type != q.Type || p.AttachType != q.AttachType || p.AttachTo != q.AttachTo || p.SectionName != q.SectionName {
			t.Errorf("%s: probe %s %s %q, rdonly %s %s %q", name, p.Type, p.AttachType, p.AttachTo, q.Type,
				q.AttachType, q.AttachTo)
		}
	}
	if a, b := slices.Sorted(maps.Keys(pr.Maps)), slices.Sorted(maps.Keys(rd.Maps)); !slices.Equal(a, b) {
		t.Fatalf("maps differ: probe %v, rdonly %v", a, b)
	}
	for name, m := range pr.Maps {
		n := rd.Maps[name]
		if m.Type != n.Type || m.KeySize != n.KeySize || m.ValueSize != n.ValueSize || m.MaxEntries != n.MaxEntries ||
			m.Pinning != n.Pinning || m.Flags != n.Flags {
			t.Errorf("map %s: probe %v, rdonly %v", name, m, n)
		}
	}
	rawPr, _ := Raw(ObjectTraceProc)
	if slices.Equal(rawPr, readerGenerated[ObjectTraceProc].raw) {
		t.Fatal("the two builds of trace_proc are the same bytes")
	}
}

// TestLoadPicksTheKernelsReader: Load hands out the build KernelReader chose, and an object with one build is
// that build for either reader.
func TestLoadPicksTheKernelsReader(t *testing.T) {
	spec, err := Load(ObjectTraceProc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := LoadReader(ObjectTraceProc, KernelReader().Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(kernelReadsOf(spec), kernelReadsOf(want)) {
		t.Fatalf("Load gave another build than %s's", KernelReader().Reader)
	}
	a, err := LoadReader(ObjectCgroupTrack, ReaderRdonly)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadReader(ObjectCgroupTrack, ReaderProbe)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Programs) != len(b.Programs) {
		t.Fatal("cgroup_track's one build differs by reader")
	}
}
