// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// runInsts runs a built program against one seccomp_data record and returns the verdict.
func runInsts(t *testing.T, insts []bpf.Instruction, data []byte) uint32 {
	t.Helper()
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	ret, err := vm.Run(data)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return uint32(ret)
}

// TestMemfdSealFilterDecisions is the memfd_create arm (SEMANTICS §4): with the sealing arm installed, a
// memfd_create that omits MFD_NOEXEC_SEAL — the flag that clears and seals the new file's execute bits, so
// the kernel refuses to exec it — is refused with EACCES, and one that sets it is allowed, so a data memfd
// still works. MFD_EXEC and flags=0 both produce an executable image and are refused, and so is MFD_HUGETLB
// with or without the seal flag, because hugetlbfs does not enforce F_SEAL_EXEC. The refusing arm (a kernel
// below 6.3) answers every memfd_create ENOSYS, the seal flag included; with no arm every one is allowed.
//
// Spec: docs/p0/enforce-landlock.md R11a, R17.
func TestMemfdSealFilterDecisions(t *testing.T) {
	cases := []struct {
		name  string
		arch  Arch
		arm   MemfdArm
		nr    uint32
		flags uint64
		want  uint32
	}{
		{"x86 bare, sealed -> EACCES", ArchX86_64, MemfdSealed, 319, 0, retEACCES},
		{"x86 MFD_EXEC, sealed -> EACCES", ArchX86_64, MemfdSealed, 319, 0x10, retEACCES},
		{"x86 MFD_NOEXEC_SEAL, sealed -> allow", ArchX86_64, MemfdSealed, 319, mfdNoexecSeal, retAllow},
		{"x86 NOEXEC_SEAL|CLOEXEC, sealed -> allow", ArchX86_64, MemfdSealed, 319, mfdNoexecSeal | 0x1, retAllow},
		{"x86 HUGETLB|NOEXEC_SEAL, sealed -> EACCES", ArchX86_64, MemfdSealed, 319, mfdHugetlb | mfdNoexecSeal, retEACCES},
		{"x86 HUGETLB|NOEXEC_SEAL|2M, sealed -> EACCES", ArchX86_64, MemfdSealed, 319, mfdHugetlb | mfdNoexecSeal | 21<<26, retEACCES},
		{"x86 HUGETLB, sealed -> EACCES", ArchX86_64, MemfdSealed, 319, mfdHugetlb, retEACCES},
		{"x86 bare, open -> allow", ArchX86_64, MemfdOpen, 319, 0, retAllow},
		{"x86 HUGETLB, open -> allow", ArchX86_64, MemfdOpen, 319, mfdHugetlb, retAllow},
		{"x86 bare, refused -> ENOSYS", ArchX86_64, MemfdRefused, 319, 0, retENOSYS},
		{"x86 CLOEXEC, refused -> ENOSYS", ArchX86_64, MemfdRefused, 319, 0x1, retENOSYS},
		{"x86 NOEXEC_SEAL, refused -> ENOSYS", ArchX86_64, MemfdRefused, 319, mfdNoexecSeal, retENOSYS},
		{"arm64 bare, sealed -> EACCES", ArchARM64, MemfdSealed, 279, 0, retEACCES},
		{"arm64 MFD_NOEXEC_SEAL, sealed -> allow", ArchARM64, MemfdSealed, 279, mfdNoexecSeal, retAllow},
		{"arm64 HUGETLB|NOEXEC_SEAL, sealed -> EACCES", ArchARM64, MemfdSealed, 279, mfdHugetlb | mfdNoexecSeal, retEACCES},
		{"arm64 bare, open -> allow", ArchARM64, MemfdOpen, 279, 0, retAllow},
		{"arm64 bare, refused -> ENOSYS", ArchARM64, MemfdRefused, 279, 0, retENOSYS},
		{"arm64 NOEXEC_SEAL, refused -> ENOSYS", ArchARM64, MemfdRefused, 279, mfdNoexecSeal, retENOSYS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insts, err := BuildFilterMemfd(tc.arch, false, tc.arm)
			if err != nil {
				t.Fatal(err)
			}
			// memfd_create(name, flags): the name pointer is args[0], flags args[1].
			if got := runInsts(t, insts, seccompData(tc.arch, tc.nr, 0, tc.flags)); got != tc.want {
				t.Errorf("memfd_create flags=%#x arm=%s -> %#x, want %#x", tc.flags, tc.arm, got, tc.want)
			}
		})
	}
}

// TestMemfdArmFor is the arm Prepare picks (SEMANTICS §4): none for a contract with no exec: section, one that set
// exec.anonymous: true, or a hand-built table with no Contract; the sealing arm on a kernel that honours
// MFD_NOEXEC_SEAL; and, on one that does not (below 6.3), the arm that refuses every memfd_create. Before
// the refusing arm existed, such a kernel got no arm at all, and a restricted-exec run's only closure of the
// memfd vector was the supervisor's racy walk.
//
// Spec: docs/p0/enforce-landlock.md R11a.
func TestMemfdArmFor(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }
	restricted := &agent.Contract{Exec: &agent.ExecSection{Allow: []string{"/bin/true"}}}
	optedIn := &agent.Contract{Exec: &agent.ExecSection{Allow: []string{"/bin/true"}, Anonymous: true}}
	unrestricted := &agent.Contract{}
	cases := []struct {
		name string
		c    *agent.Contract
		seal func() bool
		want MemfdArm
	}{
		{"restricted, kernel >= 6.3", restricted, yes, MemfdSealed},
		{"restricted, kernel < 6.3", restricted, no, MemfdRefused},
		{"exec.anonymous, kernel >= 6.3", optedIn, yes, MemfdOpen},
		{"exec.anonymous, kernel < 6.3", optedIn, no, MemfdOpen},
		{"no exec: section", unrestricted, no, MemfdOpen},
		{"no Contract", nil, no, MemfdOpen},
		// ADR 0048 (1): a deny-list section restricts no image, so it is read as no exec: section.
		{"deny-list", &agent.Contract{Exec: &agent.ExecSection{Deny: []string{"git push"}}}, no, MemfdOpen},
		{"deny-list, empty", &agent.Contract{Exec: &agent.ExecSection{Deny: []string{}}}, no, MemfdOpen},
		{"allow: [] beside deny", &agent.Contract{Exec: &agent.ExecSection{Allow: []string{}, Deny: []string{"git push"}}}, no, MemfdRefused},
	}
	for _, tc := range cases {
		if got := memfdArmFor(tc.c, tc.seal, false); got != tc.want {
			t.Errorf("%s: arm %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestMemfdArmDroppedWhereThePlaneMaps is enforce-plane R27's memfd half (ADR 0024 (13), TIER3-PLAN T14): at tiers 2
// and 3, a run a plane mode decides, whose loaded and probed hooks include step C's mmap_file and file_mprotect
// (Run.PlaneMaps), has no arm refusing every memfd_create on a kernel without MFD_NOEXEC_SEAL: bprm_check refuses an
// anonymous image's exec and mmap_file its PROT_EXEC mapping, race-free, so a data memfd need not be refused with
// them. The sealing arm stays where the kernel honours the flag (defense in depth), and a run the plane does not
// decide (tier 1, the fanotify fallback) keeps the refusing arm. Prepare threads the flag from the run through.
func TestMemfdArmDroppedWhereThePlaneMaps(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }
	restricted := &agent.Contract{Exec: &agent.ExecSection{Allow: []string{"/bin/true"}}}
	for _, tc := range []struct {
		name  string
		seal  func() bool
		plane bool
		want  MemfdArm
	}{
		{"no plane, kernel < 6.3", no, false, MemfdRefused},
		{"plane maps, kernel < 6.3", no, true, MemfdOpen},
		{"plane maps, kernel >= 6.3", yes, true, MemfdSealed},
		{"no plane, kernel >= 6.3", yes, false, MemfdSealed},
	} {
		if got := memfdArmFor(restricted, tc.seal, tc.plane); got != tc.want {
			t.Errorf("%s: arm %s, want %s", tc.name, got, tc.want)
		}
		rt := &agent.RuleTable{Contract: restricted}
		fake := &fakeSyscalls{abi: 6}
		h, err := New(Options{syscalls: fake, sealSupported: tc.seal}).Prepare(context.Background(), rt,
			Run{PlaneMaps: tc.plane})
		if err != nil {
			t.Fatalf("%s: Prepare: %v", tc.name, err)
		}
		got, _ := h.SeccompFilter()
		want, err := assembleFilter(NativeArch(), filterOpts{abi: 6, memfd: tc.want, signals: false, procScope: true,
			unixBinds: rt.HostSocketsRefused() || rt.Contract.Net != nil, listenControl: rt.Contract.Net != nil})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: the installed filter's memfd arm is not %s", tc.name, tc.want)
		}
		_ = h.Close()
	}
}

// TestMemfdSealLeavesOtherSyscalls is the arms' non-interference: with either closing arm installed, a
// read is still allowed, an execve still notified and the keyring still notified — the memfd arm changes
// only memfd_create.
func TestMemfdSealLeavesOtherSyscalls(t *testing.T) {
	for _, arm := range []struct {
		arm   MemfdArm
		memfd uint32
	}{{MemfdSealed, retEACCES}, {MemfdRefused, retENOSYS}} {
		insts, err := BuildFilterMemfd(ArchX86_64, false, arm.arm)
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name string
			nr   uint32
			want uint32
		}{
			{"read -> allow", 0, retAllow},
			{"execve -> notify", 59, retNotify},
			{"add_key -> notify", 248, retNotify},
			{"socket -> allow", 41, retAllow},
			{"memfd_create bare", 319, arm.memfd},
		}
		for _, tc := range cases {
			if got := runInsts(t, insts, seccompData(ArchX86_64, tc.nr)); got != tc.want {
				t.Errorf("%s arm, %s: got %#x, want %#x", arm.arm, tc.name, got, tc.want)
			}
		}
	}
}

// TestMemfdSealFilterGolden keeps a human-readable dump of each closing arm's filter per arch under
// testdata/, like TestFilterGolden does for the forms with no arm (§10). The memfd arm is what a reviewer
// diffs when the tier's exec closure changes.
func TestMemfdSealFilterGolden(t *testing.T) {
	cases := []struct {
		file string
		arch Arch
		arm  MemfdArm
	}{
		{"filter_x86_64_seal.txt", ArchX86_64, MemfdSealed},
		{"filter_arm64_seal.txt", ArchARM64, MemfdSealed},
		{"filter_x86_64_memfd_refused.txt", ArchX86_64, MemfdRefused},
		{"filter_arm64_memfd_refused.txt", ArchARM64, MemfdRefused},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			insts, err := BuildFilterMemfd(tc.arch, false, tc.arm)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			for i, ins := range insts {
				fmt.Fprintf(&buf, "%3d %-16T %v\n", i, ins, ins)
			}
			path := filepath.Join("testdata", tc.file)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if !bytes.Equal(want, buf.Bytes()) {
				t.Errorf("sealed filter differs from %s:\n%s", path, buf.String())
			}
		})
	}
}

// TestMemfdNoexecSealSupportedProbe is the probe that chooses between the sealing and the refusing arm: on a
// kernel that honours the flag (this box is well past 6.3) it must report support.
func TestMemfdNoexecSealSupportedProbe(t *testing.T) {
	if fd, err := unix.MemfdCreate("probe", mfdNoexecSeal|unix.MFD_CLOEXEC); err == nil {
		_ = unix.Close(fd)
		if !MemfdNoexecSealSupported() {
			t.Error("kernel accepts MFD_NOEXEC_SEAL but MemfdNoexecSealSupported reports false")
		}
	} else {
		if MemfdNoexecSealSupported() {
			t.Error("kernel refuses MFD_NOEXEC_SEAL but MemfdNoexecSealSupported reports true")
		}
		t.Logf("kernel does not honour MFD_NOEXEC_SEAL (%v); a restricted-exec run refuses every memfd_create here", err)
	}
}

// TestPrepareMemfdArmAndCapabilityLine is the memfd arm through Prepare: a restricted-exec run's filter carries the
// closing arm this kernel supports, and a run whose contract set exec.anonymous: true carries none and
// reports exec.deny false on its capability line, since with no arm any binary the agent can read can be
// copied into a memfd and run, which exec.allow then does not bound. A run with no exec: section keeps the
// row: it restricts nothing, and nothing it asked for is missing.
func TestPrepareMemfdArmAndCapabilityLine(t *testing.T) {
	kernelArm := MemfdRefused
	if MemfdNoexecSealSupported() {
		kernelArm = MemfdSealed
	}
	optedIn := contractWith(true, true)
	optedIn.Exec.Anonymous = true
	cases := []struct {
		name     string
		c        *agent.Contract
		arm      MemfdArm
		execDeny bool
	}{
		{"exec restricted", contractWith(true, true), kernelArm, true},
		{"exec.anonymous: true", optedIn, MemfdOpen, false},
		{"no exec: section", contractWith(false, true), MemfdOpen, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Contract: tc.c}
			h, _ := prepare(t, 7, rt)
			got, ok := h.SeccompFilter()
			if !ok {
				t.Fatal("no seccomp filter")
			}
			want, err := assembleFilter(NativeArch(), filterOpts{abi: 7, memfd: tc.arm, socket: SocketArmFor(rt), procScope: true,
				unixBinds: rt.Contract == nil || rt.Contract.Net != nil, listenControl: rt.Contract == nil || rt.Contract.Net != nil,
				sourceRoute: rt.Contract == nil || rt.Contract.Net != nil, frames: rt.DecidesDatagrams()})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, want) {
				t.Errorf("the installed filter is not the %s arm's", tc.arm)
			}
			if has := h.Capabilities().Has(backend.CapExecDeny); has != tc.execDeny {
				t.Errorf("capability line exec.deny = %v, want %v", has, tc.execDeny)
			}
		})
	}
}
