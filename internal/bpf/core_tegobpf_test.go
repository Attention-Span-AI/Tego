// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// TestCORERelocationsResolve applies every CO-RE relocation of every program against the running kernel's
// BTF, without loading anything. It is the check §6 E31 describes — a field of this component's own reads
// missing from a kernel's BTF — done by name and ahead of time, rather than as a verifier tail at load, and
// it needs no privilege: /sys/kernel/btf/vmlinux is world-readable, so a CI runner that can load nothing
// still proves every relocation in the shipped objects resolves on its kernel.
//
// What it cannot prove is that the verifier accepts the programs; that is the root-only load test in
// load_integration_test.go, and bpf/README.md carries the manual procedure for it.
//
// The unix programs are the exception, on a kernel without bpf_sock_addr_kern.uaddrlen, the field they read,
// which arrived with the unix sockaddr hooks (6.7): such a kernel cannot run them, the backend's load-time probe
// leaves them out there (§5 R7), and a kernel that has the attach types without the field fails the root load
// test instead (load_integration_test.go). The enum value alone does not say it: RHEL 9's 5.14 names
// BPF_CGROUP_UNIX_CONNECT in its BTF and refuses a program of that attach type.
func TestCORERelocationsResolve(t *testing.T) {
	kernel := kernelBTF(t)
	unixHooks := kernelHasMember(kernel, "bpf_sock_addr_kern", "uaddrlen")

	for _, obj := range Objects() {
		t.Run(obj.String(), func(t *testing.T) {
			spec, err := Load(obj)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if spec.Types == nil {
				t.Fatal("the object carries no BTF; CO-RE cannot work without it")
			}
			total := 0
			for name, prog := range spec.Programs {
				if !unixHooks && slices.Contains(UnixPrograms, name) {
					t.Logf("%s: not loaded on a kernel without bpf_sock_addr_kern.uaddrlen; its relocations are not required here", name)
					continue
				}
				relos := coreRelocations(prog.Instructions)
				total += len(relos)
				if len(relos) == 0 {
					continue
				}
				fixups, err := btf.CORERelocate(relos, []*btf.Spec{kernel}, spec.ByteOrder, spec.Types.TypeID)
				if err != nil {
					t.Errorf("%s: %d relocations do not resolve against this kernel: %v", name, len(relos), err)
					continue
				}
				if len(fixups) != len(relos) {
					t.Errorf("%s: %d relocations produced %d fixups", name, len(relos), len(fixups))
				}
				// A fixup the library had to poison is one whose field does not exist on this kernel: the
				// instruction is replaced by a trap, so the program loads and then dies if it reaches it.
				// COREFixup keeps that flag unexported, so it shows up in the fixup's own rendering.
				for i, f := range fixups {
					if strings.Contains(f.String(), "poison") {
						t.Errorf("%s: relocation %s is poisoned — the program would trap if it reached that "+
							"branch on this kernel (§6 E31)", name, relos[i])
					}
				}
			}
			// arm64's uprobe object reads a probed function's arguments through struct user_pt_regs, which
			// bpf/include/common.h declares outside vmlinux.h's preserve_access_index region because its layout is
			// uapi, and reads no other kernel struct, so it has no relocation to make. Every other object, and
			// x86-64's uprobe object (struct pt_regs is a kernel type there), must have some.
			if total == 0 && !(obj == ObjectUprobeSSL && runtime.GOARCH == "arm64") {
				t.Fatalf("%s has no CO-RE relocations at all; every kernel field read must go through one", obj)
			}
			t.Logf("%s: %d relocations resolved", obj, total)
		})
	}
}

// kernelHasMember reports whether the kernel's BTF declares struct name with a member called member.
func kernelHasMember(kernel *btf.Spec, name, member string) bool {
	var st *btf.Struct
	if err := kernel.TypeByName(name, &st); err != nil {
		return false
	}
	for _, m := range st.Members {
		if m.Name == member {
			return true
		}
	}
	return false
}

// coreRelocations collects the CO-RE relocation metadata clang attached to a program's instructions.
func coreRelocations(insns asm.Instructions) []*btf.CORERelocation {
	var out []*btf.CORERelocation
	for i := range insns {
		if relo := btf.CORERelocationMetadata(&insns[i]); relo != nil {
			out = append(out, relo)
		}
	}
	return out
}
