// SPDX-License-Identifier: Apache-2.0

//go:build integration

package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
)

// TestD7NamesALegacyExclusiveAttachAbove (§6 E36) in D7, with ADR 0018 PR 2's new rows
// (cgroup/sock_create, and (7)'s cgroup/setsockopt): a program
// another manager attached the legacy way, with no BPF_F_ALLOW_MULTI, on a cgroup above D7's scratch cgroup refuses
// the row's link of that attach type, as it would refuse every run's, and the row fails naming the cause in the words a
// run's Attach refusal uses (cgroupenforce.AttachConflictHint). The rows of other attach types still attach. The
// same placement fails a run's Attach (enforce/cgroup TestAttachNamesALegacyExclusiveProgramAbove).
func TestD7NamesALegacyExclusiveAttachAbove(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("D7's cgroup attach needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	if !bpfobj.Available() {
		t.Skip("this build carries no BPF objects; D7's rows load the embedded programs (-tags tegobpf)")
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	row := func(name string) hook {
		for _, h := range hooks {
			if h.Name == name {
				return h
			}
		}
		t.Fatalf("D7 has no %s row", name)
		return hook{}
	}
	for _, tc := range []struct {
		name  string
		typ   ebpf.AttachType
		ptype ebpf.ProgramType
		other string
	}{
		{"cgroup/connect4", ebpf.AttachCGroupInet4Connect, ebpf.CGroupSockAddr, "cgroup/sock_create"},
		{"cgroup/sock_create", ebpf.AttachCGroupInetSockCreate, ebpf.CGroupSock, "cgroup/connect4"},
		{"cgroup/setsockopt", ebpf.AttachCGroupSetsockopt, ebpf.CGroupSockopt, "cgroup/sock_create"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("tego-it-d7conflict-%d", os.Getpid()))
			if err := os.Mkdir(parent, 0o755); err != nil {
				t.Skipf("cannot make a cgroup at %s: %v", parent, err)
			}
			t.Cleanup(func() { _ = os.Remove(parent) })
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tego_legacy", Type: tc.ptype, AttachType: tc.typ, License: "GPL",
				Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}})
			if err != nil {
				t.Fatalf("load a stand-in program: %v", err)
			}
			defer prog.Close()
			dir, err := os.Open(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: int(dir.Fd()), Program: prog, Attach: tc.typ}); err != nil {
				t.Fatalf("legacy-attach a stand-in %s program: %v", tc.name, err)
			}
			defer func() {
				if err := link.RawDetachProgram(link.RawDetachProgramOptions{Target: int(dir.Fd()), Program: prog, Attach: tc.typ}); err != nil {
					t.Errorf("detach the stand-in: %v", err)
				}
			}()
			scratch := filepath.Join(parent, "probe")
			if err := os.Mkdir(scratch, 0o755); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(scratch)
			cg := &scratchCgroup{path: scratch}

			res := testHook(row(tc.name), spec, cg, nil, Version{})
			if res.OK() || res.Attached || !res.Loaded {
				t.Fatalf("%s beneath a legacy exclusive program: %+v, want loaded and not attached", tc.name, res)
			}
			if !strings.Contains(res.Detail, cgroupenforce.AttachConflictHint(scratch)) {
				t.Fatalf("%s's detail does not name the conflict: %q", tc.name, res.Detail)
			}
			if other := testHook(row(tc.other), spec, cg, nil, Version{}); !other.OK() {
				t.Fatalf("%s, another attach type, failed too: %+v", tc.other, other)
			}
			st := probeState{hooks: []HookResult{res}}
			if missing := st.missingHooks(res.Tier); len(missing) != 1 || !strings.Contains(missing[0], "bpftool cgroup tree") {
				t.Fatalf("tier %s's missing list: %v", res.Tier, missing)
			}
		})
	}
}
