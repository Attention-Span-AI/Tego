// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// attachTarget is one program's hook, the kernel symbol it attaches to, and how many of that symbol's
// arguments the C declares. docs/ARCHITECTURE.md §11.1 rule 1 is the reason the second number matters: a
// program may declare fewer arguments than the kernel function has — a later kernel appending one is then
// harmless — but never more, because reading past the prototype silently reads something else.
//
// An fexit program is the exception that must declare them all: the function's return is in the context slot
// after its last argument, so a program declaring fewer would read an argument as the return (ADR 0016 (3)).
// fexit marks those, and optional marks a function not every supported kernel has (OptionalTracePrograms).
type attachTarget struct {
	program  string
	section  string
	target   string
	declared int
	fexit    bool
	optional bool
}

// targets mirrors the SEC() lines of bpf/cgroup_track.bpf.c and bpf/trace_proc.bpf.c. The CGROUP_SOCK_ADDR
// programs of cgroup_net.bpf.c are not here: they attach by attach type to a cgroup, not to a kernel symbol,
// and their context is a fixed uapi struct rather than a BTF prototype.
var targets = []attachTarget{
	{ProgCgroupMkdir, "tp_btf/cgroup_mkdir", "btf_trace_cgroup_mkdir", 2, false, false},
	{ProgCgroupRmdir, "tp_btf/cgroup_rmdir", "btf_trace_cgroup_rmdir", 2, false, false},
	{ProgSchedExec, "tp_btf/sched_process_exec", "btf_trace_sched_process_exec", 3, false, false},
	{ProgSchedExit, "tp_btf/sched_process_exit", "btf_trace_sched_process_exit", 1, false, false},
	{ProgFileOpen, "fexit/security_file_open", "security_file_open", 1, true, false},
	{ProgPathUnlink, "fexit/security_path_unlink", "security_path_unlink", 2, true, false},
	{ProgPathRename, "fexit/security_path_rename", "security_path_rename", 5, true, false},
	{ProgPathMkdir, "fexit/security_path_mkdir", "security_path_mkdir", 3, true, false},
	{ProgPathMknod, "fexit/security_path_mknod", "security_path_mknod", 4, true, false},
	{ProgPathRmdir, "fexit/security_path_rmdir", "security_path_rmdir", 2, true, false},
	{ProgPathLink, "fexit/security_path_link", "security_path_link", 3, true, false},
	{ProgPathSymlink, "fexit/security_path_symlink", "security_path_symlink", 3, true, false},
	{ProgPathTruncate, "fexit/security_path_truncate", "security_path_truncate", 1, true, false},
	{ProgFileTruncate, "fexit/security_file_truncate", "security_file_truncate", 1, true, true},
	{ProgSocketConnect, "fentry/security_socket_connect", "security_socket_connect", 2, false, false},
}

// kernelBTF loads the running kernel's BTF, or skips. It is world-readable, so this needs no privilege and
// runs in every build — which is the point: a hook that has been renamed or compiled out is a load failure
// at the worst possible moment, and this finds it without loading anything.
func kernelBTF(t *testing.T) *btf.Spec {
	t.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("this kernel exposes no BTF at /sys/kernel/btf/vmlinux; tier 2 cannot run here at all")
		}
		t.Skipf("cannot read the kernel's BTF: %v", err)
	}
	return spec
}

// TestAttachTargetsResolve asserts every tracing hook this component names exists in the running kernel's
// BTF with at least as many arguments as the C declares (§8 I2, ARCHITECTURE §11.1 rule 1).
func TestAttachTargetsResolve(t *testing.T) {
	t.Parallel()
	spec := kernelBTF(t)
	for _, tc := range targets {
		t.Run(tc.program, func(t *testing.T) {
			params, err := paramsOf(spec, tc.target)
			if err != nil && tc.optional {
				t.Skipf("SEC(%q): %s is not in this kernel (%v); the backend leaves the program out here", tc.section,
					tc.target, err)
			}
			if err != nil {
				t.Fatalf("SEC(%q): %v", tc.section, err)
			}
			if tc.fexit && tc.declared != len(params) {
				t.Fatalf("SEC(%q) declares %d arguments, %s has %d: an fexit program reads the return from the "+
					"slot after the last argument, so it must declare them all (ADR 0016 (3))", tc.section,
					tc.declared, tc.target, len(params))
			}
			if tc.declared > len(params) {
				t.Fatalf("SEC(%q) declares %d arguments, %s has %d: reading past the prototype reads "+
					"something else (ARCHITECTURE §11.1 rule 1)", tc.section, tc.declared, tc.target, len(params))
			}
			if tc.declared < len(params) {
				t.Logf("SEC(%q) declares %d of %s's %d arguments, deliberately: the rest were added after "+
					"the 6.1 floor", tc.section, tc.declared, tc.target, len(params))
			}
		})
	}
}

// TestDPathAllowlistTargets records the fact §5 R9/R10 turns on, as far as BTF can show it: the one program
// that resolves a path attaches to security_file_open, and the ones that carry raw identifiers attach to
// the security_path_* dispatchers. The kernel's btf_allowlist_d_path is a fixed set in its own source, not
// something BTF exposes, so this pins the attach points rather than the set.
func TestDPathAllowlistTargets(t *testing.T) {
	t.Parallel()
	byProgram := map[string]attachTarget{}
	for _, tc := range targets {
		byProgram[tc.program] = tc
	}
	if got := byProgram[ProgFileOpen].target; got != "security_file_open" {
		t.Fatalf("the one bpf_d_path caller attaches to %q", got)
	}
	for _, p := range []string{ProgPathUnlink, ProgPathRename, ProgPathMkdir, ProgPathMknod, ProgPathRmdir, ProgPathLink,
		ProgPathSymlink, ProgPathTruncate, ProgFileTruncate} {
		if got := byProgram[p].target; got == "security_file_open" {
			t.Fatalf("%s attaches to security_file_open; the delete/rename/mkdir hooks are never in "+
				"btf_allowlist_d_path and must carry raw identifiers instead (R9/R10)", p)
		}
	}
}

// TestSharedStructFieldsResolve is §6 E31's check done ahead of time: every field this component's own
// structs read off a kernel type must exist in the running kernel's BTF, so a CO-RE relocation failure is
// diagnosed by name here instead of as a verifier tail at load.
func TestSharedStructFieldsResolve(t *testing.T) {
	t.Parallel()
	spec := kernelBTF(t)
	cases := []struct {
		typ    string
		fields []string
	}{
		{"cgroup", []string{"kn", "self"}},
		{"kernfs_node", []string{"id"}},
		{"cgroup_subsys_state", []string{"cgroup", "parent"}},
		{"task_struct", []string{"pid", "tgid", "comm", "mm", "real_parent", "exit_code", "start_boottime"}},
		{"mm_struct", []string{"arg_start", "arg_end"}},
		{"linux_binprm", []string{"filename", "interp"}},
		{"file", []string{"f_flags", "f_inode", "f_path", "f_mode"}},
		{"inode", []string{"i_ino", "i_sb", "i_mode"}},
		{"super_block", []string{"s_dev"}},
		{"path", []string{"dentry", "mnt"}},
		{"dentry", []string{"d_name", "d_inode", "d_sb", "d_parent"}},
		{"qstr", []string{"hash_len", "name", "len"}},
		{"socket", []string{"sk", "type"}},
		{"sock", []string{"sk_protocol"}},
		{"sockaddr", []string{"sa_family"}},
		{"sockaddr_in", []string{"sin_port", "sin_addr"}},
		{"sockaddr_in6", []string{"sin6_port", "sin6_addr"}},
		{"bpf_sock_addr", []string{"user_family", "user_ip4", "user_ip6", "user_port", "protocol"}},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			var st *btf.Struct
			if err := spec.TypeByName(tc.typ, &st); err != nil {
				t.Fatalf("struct %s is not in this kernel's BTF: %v", tc.typ, err)
			}
			have := map[string]struct{}{}
			collectFields(st, have, 0)
			for _, f := range tc.fields {
				if _, ok := have[f]; !ok {
					t.Errorf("struct %s has no field %q in this kernel; a CO-RE read of it would fail at "+
						"load (§6 E31)", tc.typ, f)
				}
			}
		})
	}
}

// collectFields gathers a struct's field names, descending through anonymous members. The kernel puts several
// fields this component reads inside them — mm_struct wraps arg_start and arg_end in an anonymous
// __randomize_layout struct, for instance — and C, clang's CO-RE relocations and this check all see through
// an anonymous member alike.
func collectFields(t btf.Type, into map[string]struct{}, depth int) {
	if depth > 8 {
		return
	}
	var members []btf.Member
	switch v := btf.UnderlyingType(t).(type) {
	case *btf.Struct:
		members = v.Members
	case *btf.Union:
		members = v.Members
	default:
		return
	}
	for _, m := range members {
		if m.Name == "" {
			collectFields(m.Type, into, depth+1)
			continue
		}
		into[m.Name] = struct{}{}
	}
}

// paramsOf resolves a function or a tracepoint's BTF prototype and returns its parameters. A tp_btf target is
// a btf_trace_* typedef whose first parameter is the tracepoint's own void* context, which the BPF_PROG macro
// hides, so it is dropped here to make the count comparable with what the C declares.
func paramsOf(spec *btf.Spec, name string) ([]btf.FuncParam, error) {
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err == nil {
		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok {
			return nil, errors.New("function has no prototype in BTF")
		}
		return proto.Params, nil
	}
	var td *btf.Typedef
	if err := spec.TypeByName(name, &td); err != nil {
		return nil, err
	}
	ptr, ok := btf.UnderlyingType(td).(*btf.Pointer)
	if !ok {
		return nil, errors.New("tracepoint typedef is not a function pointer")
	}
	proto, ok := ptr.Target.(*btf.FuncProto)
	if !ok {
		return nil, errors.New("tracepoint typedef does not point at a prototype")
	}
	if len(proto.Params) == 0 {
		return nil, errors.New("tracepoint prototype has no context parameter")
	}
	return proto.Params[1:], nil
}
