// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func typeIDOf(t *testing.T, spec *btf.Spec, name string) btf.TypeID {
	t.Helper()
	for typ, err := range spec.All() {
		if err != nil {
			t.Fatal(err)
		}
		if typ.TypeName() == name {
			id, err := spec.TypeID(typ)
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
	}
	t.Fatalf("no type %s", name)
	return 0
}

// A relocation is read into the kernel member it needs, or refused when it cannot be read: a need that is
// misread would let D2 pass a kernel that lacks the member the program dereferences.
func TestNeedOfStringReadsAccessorsAndRefusesMalformedOnes(t *testing.T) {
	spec, err := btf.LoadSpec(writeFakeBTF(t, fakeKernelTypes()...))
	if err != nil {
		t.Fatal(err)
	}
	rel := func(kind, name, acc string) string {
		return "CORERelocation(" + kind + ", " + name + "[" + acc + "], local_id=" +
			strconv.Itoa(int(typeIDOf(t, spec, name))) + ")"
	}
	good := []struct {
		name string
		rs   string
		want coreNeed
	}{
		{"member", rel("byte_off", "task_struct", "0:1"), coreNeed{Type: "task_struct", Path: []string{"real_parent"}}},
		{"through an anonymous union", rel("byte_off", "cgroup", "0:0:0"), coreNeed{Type: "cgroup", Path: []string{"kn"}}},
		{"array element", rel("byte_off", "in6_addr", "0:0:3"), coreNeed{Type: "in6_addr", Path: []string{"u6_addr8", "[]"}}},
		{"type size", rel("type_size", "task_struct", "0"), coreNeed{Type: "task_struct"}},
		{"enum value", rel("enumval_value", "bpf_attach_type", "0"), coreNeed{Type: "bpf_attach_type", Enum: "BPF_CGROUP_INET4_CONNECT"}},
	}
	for _, c := range good {
		got, ok, err := needOfString(c.rs, spec)
		if err != nil || !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v ok=%v err=%v, want %+v", c.name, got, ok, err, c.want)
		}
	}
	if _, ok, err := needOfString(rel("local_type_id", "task_struct", "0"), spec); ok || err != nil {
		t.Errorf("local_type_id reads nothing of the kernel: ok=%v err=%v", ok, err)
	}
	bad := map[string]string{
		"not a relocation":       "hello",
		"member out of range":    rel("byte_off", "task_struct", "0:9"),
		"step through a pointer": rel("byte_off", "task_struct", "0:1:0"),
		"step into a scalar":     rel("byte_off", "task_struct", "0:0:0"),
		"enum index too large":   rel("enumval_value", "bpf_attach_type", "5"),
		"enum on a struct":       rel("enumval_value", "task_struct", "0"),
		"unknown kind":           rel("bogus_kind", "task_struct", "0:0"),
		"missing type id":        "CORERelocation(byte_off, task_struct[0:0], local_id=99999)",
	}
	for name, rs := range bad {
		if _, ok, err := needOfString(rs, spec); ok || err == nil {
			t.Errorf("%s: accepted (ok=%v err=%v)", name, ok, err)
		}
	}
}

func TestEssentialNameDropsTheFlavourSuffix(t *testing.T) {
	for in, want := range map[string]string{
		"task_struct":         "task_struct",
		"task_struct___old":   "task_struct",
		"task_struct___a___b": "task_struct",
		"___x":                "___x",
		"":                    "",
	} {
		if got := essentialName(in); got != want {
			t.Errorf("essentialName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCoreNeedString(t *testing.T) {
	cases := []struct {
		n    coreNeed
		want string
	}{
		{coreNeed{Type: "task_struct"}, "task_struct"},
		{coreNeed{Type: "task_struct", Path: []string{"real_parent", "tgid"}}, "task_struct.real_parent.tgid"},
		{coreNeed{Type: "in6_addr", Path: []string{"u6_addr8", "[]"}}, "in6_addr.u6_addr8[]"},
		{coreNeed{Type: "bpf_attach_type", Enum: "X"}, "bpf_attach_type::X"},
	}
	for _, c := range cases {
		if got := c.n.String(); got != c.want {
			t.Errorf("%+v = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestConfigLTOReadsGzipAndPlainAndRefusesTheUnreadable(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gz := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(s))
		w.Close()
		return b.Bytes()
	}
	if v, ok := configLTO(write("a.gz", gz("CONFIG_X=y\nCONFIG_LTO_CLANG=y\n"))); !ok || v != ltoClang {
		t.Errorf("gzip clang: %q %v", v, ok)
	}
	if v, ok := configLTO(write("b.gz", gz("CONFIG_X=y\n# CONFIG_LTO_CLANG is not set\n"))); !ok || v != ltoNone {
		t.Errorf("gzip none: %q %v", v, ok)
	}
	if v, ok := configLTO(write("config", []byte("CONFIG_LTO_CLANG=y\n"))); !ok || v != ltoClang {
		t.Errorf("plain: %q %v", v, ok)
	}
	if _, ok := configLTO(write("bad.gz", []byte("not gzip at all"))); ok {
		t.Error("a corrupt gzip must not answer: the caller then tries the next source")
	}
	if _, ok := configLTO(filepath.Join(dir, "missing")); ok {
		t.Error("a missing file must not answer")
	}
}
