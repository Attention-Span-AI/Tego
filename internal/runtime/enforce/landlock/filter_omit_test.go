// SPDX-License-Identifier: Apache-2.0

package landlock

import "testing"

// omitControlArms are the arms a root test leaves out to reach the plane's bpf and key_permission hooks from a
// governed run (enforce-plane §2.20).
var omitControlArms = map[string]bool{"bpf": true, "add_key": true, "request_key": true, "keyctl": true}

// TestFilterTestOmitLeavesOnlyTheNamedArmsOut: the seam a test build sets (filterTestOmit) takes each syscall it
// names out of the notify arm and the root-tier arm and changes nothing else. At tiers 2 and 3 the filter answers
// bpf(2) with EPERM (ADR 0033) and notifies add_key, request_key and keyctl (SEMANTICS §1), so none reaches security_bpf
// or security_key_permission; with the seam naming them each is allowed through, and every other syscall of those two
// arms is answered as before, on both architectures. The names are in both tables, so a renamed entry cannot turn the
// seam into one that omits nothing.
//
// Spec: docs/p0/enforce-landlock.md R11.
func TestFilterTestOmitLeavesOnlyTheNamedArmsOut(t *testing.T) {
	was := filterTestOmit
	t.Cleanup(func() { filterTestOmit = was })
	o := filterOpts{abi: minTruncateABI, rootTier: true}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		arms := append(append([]sysNR(nil), tab.Notify...), tab.RootDeny...)
		filterTestOmit = func(string) bool { return false }
		product := map[string]uint32{}
		for _, s := range arms {
			product[s.Name] = planeVerdict(t, arch, o, s.NR)
		}
		if product["bpf"] != retEPERM || product["keyctl"] != retNotify || product["add_key"] != retNotify || product["request_key"] != retNotify {
			t.Fatalf("%s: the product filter answers bpf %#x and keyctl %#x, want EPERM and a notification", arch, product["bpf"], product["keyctl"])
		}
		filterTestOmit = func(name string) bool { return omitControlArms[name] }
		named := 0
		for _, s := range arms {
			got := planeVerdict(t, arch, o, s.NR)
			if omitControlArms[s.Name] {
				named++
				if got != retAllow {
					t.Errorf("%s: %s is answered %#x with the seam naming it, want allow", arch, s.Name, got)
				}
			} else if got != product[s.Name] {
				t.Errorf("%s: %s is answered %#x with the seam naming others, %#x without it", arch, s.Name, got, product[s.Name])
			}
		}
		if named != len(omitControlArms) {
			t.Errorf("%s: %d of the %d named syscalls are in the notify and root-tier arms", arch, named, len(omitControlArms))
		}
	}
}
