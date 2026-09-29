// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strconv"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// An existence relocation is no need: the loader resolves it to 0 on a kernel without the target, so D2 must not
// fail that kernel over it, while a layout relocation on the same type stays a need.
func TestNeedOfSkipsExistenceRelocations(t *testing.T) {
	spec, err := btf.LoadSpec(writeFakeBTF(t, fakeKernelTypes()...))
	if err != nil {
		t.Fatal(err)
	}
	var id btf.TypeID
	for typ, err := range spec.All() {
		if err != nil {
			t.Fatal(err)
		}
		if typ.TypeName() == "task_struct" {
			if id, err = spec.TypeID(typ); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	rel := func(kind string) string {
		return "CORERelocation(" + kind + ", task_struct[0:1], local_id=" + strconv.Itoa(int(id)) + ")"
	}
	for _, kind := range []string{"field_exists", "type_exists", "type_matches", "enumval_exists"} {
		if n, ok, err := needOfString(rel(kind), spec); err != nil || ok {
			t.Errorf("%s: need %v ok %v err %v, want none", kind, n, ok, err)
		}
	}
	if n, ok, err := needOfString(rel("byte_off"), spec); err != nil || !ok || n.Type != "task_struct" {
		t.Errorf("byte_off: %v %v %v, want a need", n, ok, err)
	}
}
