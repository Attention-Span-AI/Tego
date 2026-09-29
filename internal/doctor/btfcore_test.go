// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// writeFakeBTF marshals types into a raw BTF file, as /sys/kernel/btf/vmlinux is, and returns its path.
func writeFakeBTF(t *testing.T, types ...btf.Type) string {
	t.Helper()
	b, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeKernelTypes is a small kernel: a task_struct without start_boottime, a cgroup whose kn sits in an
// anonymous union, and an enum.
func fakeKernelTypes() []btf.Type {
	u32 := &btf.Int{Name: "u32", Size: 4}
	u64 := &btf.Int{Name: "u64", Size: 8}
	task := &btf.Struct{Name: "task_struct", Size: 16}
	task.Members = []btf.Member{
		{Name: "tgid", Type: u32},
		{Name: "real_parent", Type: &btf.Pointer{Target: task}, Offset: 64},
	}
	kn := &btf.Struct{Name: "kernfs_node", Size: 8, Members: []btf.Member{{Name: "id", Type: u64}}}
	anon := &btf.Union{Size: 8, Members: []btf.Member{{Name: "kn", Type: &btf.Pointer{Target: kn}}}}
	cg := &btf.Struct{Name: "cgroup", Size: 8, Members: []btf.Member{{Type: anon}}}
	arr := &btf.Struct{Name: "in6_addr", Size: 16, Members: []btf.Member{{Name: "u6_addr8",
		Type: &btf.Array{Type: &btf.Int{Name: "u8", Size: 1}, Index: u32, Nelems: 16}}}}
	en := &btf.Enum{Name: "bpf_attach_type", Size: 4, Values: []btf.EnumValue{{Name: "BPF_CGROUP_INET4_CONNECT"}}}
	return []btf.Type{task, cg, arr, en}
}

func needs(n ...coreNeed) func() ([]coreNeed, error) {
	return func() ([]coreNeed, error) { return n, nil }
}

// setBTFPath points D2 at path for the test.
func setBTFPath(t *testing.T, path string) {
	t.Helper()
	prev := btfPath
	t.Cleanup(func() { btfPath = prev })
	btfPath = path
}

// TestBTFProbeNamesAMissingField is enforce-cgroup-observe.md E31: D2 parses the kernel's BTF and checks every
// type, member and enum value the embedded objects read through CO-RE, so a kernel that lacks one fails D2
// with the member named, ahead of any program load. A member reached through an anonymous union, an array
// element and an enum value are found as the loader finds them.
func TestBTFProbeNamesAMissingField(t *testing.T) {
	setBTFPath(t, writeFakeBTF(t, fakeKernelTypes()...))
	present := []coreNeed{
		{Type: "task_struct", Path: []string{"real_parent"}, Objects: []string{"trace_proc"}},
		{Type: "task_struct", Path: []string{"tgid"}, Objects: []string{"trace_proc"}},
		{Type: "cgroup", Path: []string{"kn"}, Objects: []string{"cgroup_track"}},
		{Type: "in6_addr", Path: []string{"u6_addr8", "[]"}, Objects: []string{"trace_proc"}},
		{Type: "bpf_attach_type", Enum: "BPF_CGROUP_INET4_CONNECT", Objects: []string{"cgroup_net"}},
		{Type: "task_struct", Objects: []string{"trace_proc"}},
	}
	if r := probeBTFWith(needs(present...)); !r.OK || r.Fix != "" {
		t.Fatalf("every need present: %+v, want OK", r)
	}

	missing := append(append([]coreNeed(nil), present...),
		coreNeed{Type: "task_struct", Path: []string{"start_boottime"}, Objects: []string{"trace_proc"}},
		coreNeed{Type: "cgroup", Path: []string{"kn", "hierarchy_id"}, Objects: []string{"cgroup_track"}},
		coreNeed{Type: "sock", Path: []string{"sk_protocol"}, Objects: []string{"trace_proc"}},
		coreNeed{Type: "bpf_attach_type", Enum: "BPF_CGROUP_UNIX_CONNECT", Objects: []string{"cgroup_net"}},
	)
	r := probeBTFWith(needs(missing...))
	if r.OK || r.Fix == "" {
		t.Fatalf("needs the kernel lacks: %+v, want not OK with a fix", r)
	}
	for _, want := range []string{
		"field task_struct.start_boottime not in the kernel's BTF",
		"type sock not in the kernel's BTF",
		"enum value BPF_CGROUP_UNIX_CONNECT not in the kernel's BTF",
		"(trace_proc:",
	} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("detail %q does not name %q", r.Detail, want)
		}
	}
	// kn is a pointer, and CO-RE reads across a pointer as a relocation of its own on the pointed-to type, so a
	// path does not continue through one.
	if !strings.Contains(r.Detail, "cgroup.kn.hierarchy_id") {
		t.Errorf("detail %q does not name cgroup.kn.hierarchy_id", r.Detail)
	}
	for _, have := range []string{"real_parent (", "tgid (", "u6_addr8[]"} {
		if strings.Contains(r.Detail, have) {
			t.Errorf("detail %q names %q, which the kernel has", r.Detail, have)
		}
	}
}

// TestBTFProbeRefusesUnparsableBTF: a file at the BTF path that cilium/ebpf cannot parse is no BTF for a
// program load, so D2 fails rather than pass on the file's presence alone.
func TestBTFProbeRefusesUnparsableBTF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(path, []byte(strings.Repeat("b", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	setBTFPath(t, path)
	r := probeBTFWith(needs())
	if r.OK || r.Fix == "" || !strings.Contains(r.Detail, "parse") {
		t.Errorf("%+v, want not OK, a parse failure and a fix", r)
	}
}
