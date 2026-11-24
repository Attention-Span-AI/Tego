// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// TestNamespaceArm: unshare(CLONE_NEWUSER|CLONE_NEWNS) copied the mount tree into mounts with none of tier 2's
// fanotify marks, and a deny_read fanotify alone enforced was read there. An unshare or clone asking for a new mount
// or user namespace, and every setns, now goes to the supervisor, which refuses it; a thread's clone and an unshare
// of other namespaces are left alone. A new cgroup or process-id namespace goes there too (2026-11-18): a root-level
// run whose agent holds CAP_SYS_ADMIN made one rooted at its own scope, where its cgroup path read "0::/".
func TestNamespaceArm(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tbl, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		insts, err := buildFilter(arch, filterOpts{abi: 7})
		if err != nil {
			t.Fatal(err)
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatal(err)
		}
		thread := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD)
		for _, tc := range []struct {
			name  string
			nr    uint32
			flags uint64
			want  uint32
		}{
			{"unshare user+mount", tbl.Unshare, unix.CLONE_NEWUSER | unix.CLONE_NEWNS, retNotify},
			{"unshare mount", tbl.Unshare, unix.CLONE_NEWNS, retNotify},
			{"unshare user", tbl.Unshare, unix.CLONE_NEWUSER, retNotify},
			{"unshare cgroup", tbl.Unshare, unix.CLONE_NEWCGROUP, retNotify},
			{"unshare pid", tbl.Unshare, unix.CLONE_NEWPID, retNotify},
			{"unshare cgroup+pid", tbl.Unshare, unix.CLONE_NEWCGROUP | unix.CLONE_NEWPID, retNotify},
			{"unshare files", tbl.Unshare, unix.CLONE_FILES, unix.SECCOMP_RET_ALLOW},
			{"unshare net+uts+ipc", tbl.Unshare, unix.CLONE_NEWNET | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC, unix.SECCOMP_RET_ALLOW},
			{"clone a thread", tbl.Clone, thread, unix.SECCOMP_RET_ALLOW},
			{"clone a process", tbl.Clone, uint64(unix.SIGCHLD), unix.SECCOMP_RET_ALLOW},
			{"clone into a user namespace", tbl.Clone, uint64(unix.SIGCHLD) | unix.CLONE_NEWUSER, retNotify},
			{"clone into a cgroup namespace", tbl.Clone, uint64(unix.SIGCHLD) | unix.CLONE_NEWCGROUP, retNotify},
			{"clone into a pid namespace", tbl.Clone, uint64(unix.SIGCHLD) | unix.CLONE_NEWPID, retNotify},
			{"setns", tbl.Setns, 0, retNotify},
		} {
			got, err := vm.Run(seccompData(arch, tc.nr, tc.flags))
			if err != nil {
				t.Fatal(err)
			}
			if uint32(got) != tc.want {
				t.Errorf("%s %s: filter returned %#x, want %#x", arch, tc.name, got, tc.want)
			}
		}
	}
}
