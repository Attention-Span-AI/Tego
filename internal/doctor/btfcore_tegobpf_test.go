// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package doctor

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// TestCORENeedsOfTheObjects is enforce-cgroup-observe.md E31's derivation: D2's list of what the objects read is
// taken from their CO-RE relocations, and it names the members the C sources read. It also fails when a
// cilium/ebpf upgrade changes how a relocation prints (coreReloString), which the list is read from.
func TestCORENeedsOfTheObjects(t *testing.T) {
	list, err := objectCORENeeds()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string][]string{}
	for _, n := range list {
		names[n.String()] = n.Objects
	}
	for need, obj := range map[string]string{
		"task_struct.start_boottime": "trace_proc",
		"task_struct.real_parent":    "trace_proc",
		"file.f_flags":               "trace_proc",
		"cgroup.kn":                  "cgroup_track",
		"kernfs_node.id":             "cgroup_track",
	} {
		if !slices.Contains(names[need], obj) {
			t.Errorf("needs %v: %s is not listed for %s", names, need, obj)
		}
	}
	for _, n := range list {
		if strings.Contains(n.Type, "___") || n.Type == "" {
			t.Errorf("need %+v: the type is not named as the kernel names it", n)
		}
	}
}

// TestCORENeedsMatchTheRelocations is E31's agreement check: against a kernel whose BTF lacks one member the
// programs read, the members D2 names are exactly those whose relocations the loader (btf.CORERelocate) would
// poison. The fake kernel is the objects' own copies of the kernel types, which carry every member the
// programs read, with task_struct.start_boottime taken out.
func TestCORENeedsMatchTheRelocations(t *testing.T) {
	list, err := objectCORENeeds()
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{}
	for _, n := range list {
		wanted[n.Type] = true
	}
	var kernelTypes []btf.Type
	for _, o := range bpfobj.Objects() {
		spec, err := bpfobj.Load(o) // a fresh parse of the object: its types are this test's to change
		if err != nil {
			t.Fatal(err)
		}
		for typ, err := range spec.Types.All() {
			if err != nil {
				t.Fatal(err)
			}
			name := essentialName(typ.TypeName())
			if !wanted[name] {
				continue
			}
			if st, ok := typ.(*btf.Struct); ok && name == "task_struct" {
				st.Members = slices.DeleteFunc(st.Members, func(m btf.Member) bool { return m.Name == "start_boottime" })
			}
			kernelTypes = append(kernelTypes, typ)
		}
	}
	b, err := btf.NewBuilder(kernelTypes, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	got := missingCORE(kernel, list)
	if len(got) != 1 || !strings.HasPrefix(got[0], "task_struct.start_boottime (") {
		t.Errorf("missing = %q, want task_struct.start_boottime alone", got)
	}

	// The loader's own verdict on the same kernel, relocation by relocation.
	poisoned := map[string]bool{}
	for _, o := range bpfobj.Objects() {
		spec, err := bpfobj.Load(o)
		if err != nil {
			t.Fatal(err)
		}
		for name, prog := range spec.Programs {
			if o == bpfobj.ObjectCgroupNet && slices.Contains(bpfobj.UnixPrograms, name) {
				continue
			}
			var relos []*btf.CORERelocation
			for i := range prog.Instructions {
				if r := btf.CORERelocationMetadata(&prog.Instructions[i]); r != nil {
					relos = append(relos, r)
				}
			}
			if len(relos) == 0 {
				continue
			}
			fixups, err := btf.CORERelocate(relos, []*btf.Spec{kernel}, spec.ByteOrder, spec.Types.TypeID)
			if err != nil {
				t.Fatalf("%s/%s: %v", o, name, err)
			}
			for i, f := range fixups {
				if !strings.Contains(f.String(), "poison") {
					continue
				}
				n, ok, err := needOf(relos[i], spec.Types)
				if err != nil || !ok {
					t.Fatalf("%s: %v", relos[i], err)
				}
				poisoned[n.String()] = true
			}
		}
	}
	if len(poisoned) != 1 || !poisoned["task_struct.start_boottime"] {
		t.Errorf("the loader poisons %v, want task_struct.start_boottime alone", poisoned)
	}
}

// TestBTFProbeOnThisKernel: every need resolves against the running kernel's BTF on the machines this suite
// runs on, all of them at or above the tested floor, so D2 passes there.
func TestBTFProbeOnThisKernel(t *testing.T) {
	r := probeBTF()
	if strings.Contains(r.Detail, "no such file") {
		t.Skipf("no kernel BTF: %s", r.Detail)
	}
	if !r.OK {
		t.Fatalf("D2 on this kernel: %+v", r)
	}
	t.Log(r.Detail)
}
