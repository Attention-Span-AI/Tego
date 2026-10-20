// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// modeBitsTempDirs stands ext4 in for the filesystem of every directory a test walks that modeBitsFS does not list,
// procfs aside, so a test of how the search check reads mode bits, ACLs and procfs does not depend on the filesystem
// TMPDIR lies on: on ZFS or an NFS home every directory would be unsure. Where TMPDIR is
// on a listed filesystem, as in CI and the KVM guest, it changes nothing.
func modeBitsTempDirs(t *testing.T) {
	t.Helper()
	prev := dirFSType
	t.Cleanup(func() { dirFSType = prev })
	dirFSType = func(fd int) (uint32, error) {
		fsType, err := prev(fd)
		if err == nil && fsType != unix.PROC_SUPER_MAGIC && !modeBitsFS(fsType) {
			return unix.EXT4_SUPER_MAGIC, nil
		}
		return fsType, err
	}
}

// TestExecImageHoldsTheTaskToSearchPermission: at tiers cgroup and bpflsm the supervisor
// walks an exec's pathname as root, so its walk passes directories the task cannot search. A miss answered from that
// walk (ENOENT, R16b (0)) then told the agent whether a name exists in a directory it cannot list: a root-owned 0700
// directory answered 126 for a present file and 127 for an absent one. The walk now holds the task's own search
// permission to every directory it looks a component up in, as link_path_walk's may_lookup does: a directory the task
// is sure not to be able to search answers EACCES there, present name or absent, the kernel's own answer; a directory
// whose answer is not sure turns a failed walk into EACCES and leaves a walk that reached a file alone; a task that
// can search (its class has the bit, or it holds CAP_DAC_READ_SEARCH in this process's user namespace) misses with
// ENOENT as before. The test is the owner of every directory, so its own lookups pass them all, as root's do; the
// task's credentials are another user's.
func TestExecImageHoldsTheTaskToSearchPermission(t *testing.T) {
	tid := selfTask(t)
	modeBitsTempDirs(t)
	me, err := sys.ReadTaskCreds(tid)
	if err != nil {
		t.Fatal(err)
	}
	other := me
	other.FSUID, other.EUID, other.FSGID, other.EGID, other.Groups, other.CapEff = me.FSUID+1, me.EUID+1, me.FSGID+1, me.EGID+1, nil, 0
	groupMate := other
	groupMate.Groups = []uint32{me.FSGID}
	reader := other
	reader.CapEff = 1 << unix.CAP_DAC_READ_SEARCH

	base := t.TempDir()
	mkdir := func(rel string, mode os.FileMode) string {
		p := filepath.Join(base, rel)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	file := func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "present"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	open := mkdir("open", 0o755)
	closed := mkdir("closed", 0o700)
	group := mkdir("group", 0o710)
	file(open)
	file(closed)
	file(group)
	inner := mkdir("open/inner", 0o700)
	file(inner)
	if err := os.Symlink("../closed/absent", filepath.Join(open, "to-closed-absent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../closed/present", filepath.Join(open, "to-closed-present")); err != nil {
		t.Fatal(err)
	}
	// An access ACL that denies the task's user a 0755 directory: an unsure directory, the
	// realistic one. Below it, a 0700 directory the task is sure not to search, which the check still reaches.
	acl := mkdir("acl", 0o755)
	file(acl)
	aclClosed := mkdir("acl/closed", 0o700)
	file(aclClosed)
	hasACL := setDenyACL(t, acl, other.FSUID)

	// The walks start at a descriptor of base (execveat's dirfd), as the kernel's walk from a dirfd does: the directories
	// above it (a 0700 temporary directory) are not looked up in, and so not checked.
	baseFD, err := unix.Open(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(baseFD) })
	prevCreds, prevChecked, prevNS := taskCreds, searchChecked, sameUserNS
	t.Cleanup(func() { taskCreds, searchChecked, sameUserNS = prevCreds, prevChecked, prevNS })
	unreadable := errors.New("no creds")
	for _, c := range []struct {
		name    string
		creds   *sys.TaskCreds // nil: unreadable
		checked bool
		sameNS  bool
		path    string
		want    unix.Errno // 0: the walk reaches the file
	}{
		{"searchable, absent", &other, true, true, "open/absent", unix.ENOENT},
		{"searchable, present", &other, true, true, "open/present", 0},
		{"a component that is a file", &other, true, true, "open/present/x", unix.ENOTDIR},
		{"closed, absent", &other, true, true, "closed/absent", unix.EACCES},
		{"closed, present", &other, true, true, "closed/present", unix.EACCES},
		{"closed below an open one", &other, true, true, "open/inner/absent", unix.EACCES},
		{"closed, then ..", &other, true, true, "closed/../open/present", unix.EACCES},
		{"a symlink into a closed one, absent", &other, true, true, "open/to-closed-absent", unix.EACCES},
		{"a symlink into a closed one, present", &other, true, true, "open/to-closed-present", unix.EACCES},
		{"the group's class", &groupMate, true, true, "group/absent", unix.ENOENT},
		{"the group's class, present", &groupMate, true, true, "group/present", 0},
		{"the owner", &me, true, true, "closed/absent", unix.ENOENT},
		{"CAP_DAC_READ_SEARCH here", &reader, true, true, "closed/absent", unix.ENOENT},
		{"CAP_DAC_READ_SEARCH in another user namespace, absent", &reader, true, false, "closed/absent", unix.EACCES},
		{"CAP_DAC_READ_SEARCH in another user namespace, present", &reader, true, false, "closed/present", 0},
		{"credentials unreadable, absent", nil, true, true, "closed/absent", unix.EACCES},
		{"credentials unreadable, present", nil, true, true, "closed/present", 0},
		{"not checked (tier landlock)", &other, false, true, "closed/absent", unix.ENOENT},
		{"an access ACL, absent", &other, true, true, "acl/absent", unix.EACCES},
		{"an access ACL, present", &other, true, true, "acl/present", 0},
		{"closed below an access ACL, present", &other, true, true, "acl/closed/present", unix.EACCES},
		{"closed below an access ACL, absent", &other, true, true, "acl/closed/absent", unix.EACCES},
		{"closed below an unsure CAP_DAC_READ_SEARCH, through an ACL", &reader, true, false, "acl/closed/present", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if strings.HasPrefix(c.path, "acl/") && !hasACL {
				t.Skip("no access ACL could be set here")
			}
			creds := c.creds
			taskCreds = func(int) (sys.TaskCreds, error) {
				if creds == nil {
					return sys.TaskCreds{}, unreadable
				}
				return *creds, nil
			}
			checked, sameNS := c.checked, c.sameNS
			searchChecked = func() bool { return checked }
			sameUserNS = func(int) bool { return sameNS }
			p := c.path
			img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: int32(baseFD), path: p, joined: filepath.Join(base, p)})
			switch {
			case c.want == 0 && err != nil:
				t.Errorf("%s: %v, want the walk to reach the file", p, err)
			case c.want != 0 && !errors.Is(err, c.want):
				t.Errorf("%s: %v, want %v", p, err, c.want)
			}
			// A file reached through an unsure directory says so, and only then (execImage.unsure): nothing read from
			// it may change the task's errno.
			wantUnsure := c.name != "searchable, present" && c.name != "the group's class, present"
			if c.want == 0 && img.unsure != wantUnsure {
				t.Errorf("%s: unsure = %v, want %v", p, img.unsure, wantUnsure)
			}
		})
	}
}

// setDenyACL gives the 0755 directory dir the access ACL setfacl -m u:<uid>:--- would (user::rwx, user:<uid>:---,
// group::r-x, mask::r-x, other::r-x), written as the system.posix_acl_access xattr itself so that no setfacl binary is
// needed (the KVM guest has none). false, logged, where the filesystem takes no ACL.
func setDenyACL(t *testing.T, dir string, uid uint32) bool {
	t.Helper()
	const undefined = 0xffffffff
	entry := func(tag, perm uint16, id uint32) []byte {
		return []byte{byte(tag), byte(tag >> 8), byte(perm), byte(perm >> 8), byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24)}
	}
	b := []byte{2, 0, 0, 0}                     // POSIX_ACL_XATTR_VERSION, little-endian
	b = append(b, entry(0x01, 7, undefined)...) // ACL_USER_OBJ
	b = append(b, entry(0x02, 0, uid)...)       // ACL_USER
	b = append(b, entry(0x04, 5, undefined)...) // ACL_GROUP_OBJ
	b = append(b, entry(0x10, 5, undefined)...) // ACL_MASK
	b = append(b, entry(0x20, 5, undefined)...) // ACL_OTHER
	if err := unix.Setxattr(dir, "system.posix_acl_access", b, 0); err != nil {
		t.Logf("setting an access ACL on %s: %v; the access-ACL cases are skipped", dir, err)
		return false
	}
	return true
}

// TestExecImageMagicLinksOfAnotherProcessAreUnsure: the walk followed a procfs magic link
// (/proc/<pid>/cwd, root, fd/N, ns/*) with this process's own ptrace rights, which the task may not hold over that
// process (a root process for an agent of another user; any process outside the agent's Landlock domain). A miss
// behind the link was then ENOENT where the kernel answers the task EACCES, so the agent learned whether a name exists
// in a directory it cannot look into: 126 for /proc/<pid>/cwd/present and 127 for /proc/<pid>/cwd/absent. A link of
// another process is now an unsure step: a walk through it that fails is EACCES, a walk that reaches a file says it
// was unsure. The task's own thread group's links (/proc/self, /proc/thread-self, /dev/fd, /proc/<tgid>, any of its
// threads' directories) are followed as before, and a miss behind them is still ENOENT. The
// top-level /proc/<tid> of a non-leader thread of the group, and the task/<tid> directories beneath it, are the
// group's own too (ptrace_may_access lets a thread group at itself), where they were unsure and a miss behind them was
// EACCES where the kernel answers ENOENT. The task is this test; the other process is a sleep whose cwd holds the file.
func TestExecImageMagicLinksOfAnotherProcessAreUnsure(t *testing.T) {
	tid := selfTask(t)
	modeBitsTempDirs(t)
	pid := os.Getpid()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "present"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	other := strconv.Itoa(spawnTask(t, dir, d))
	fd := strconv.Itoa(int(d.Fd()))
	// Another thread of this thread group: the kernel lets a thread group at itself whichever thread's directory names it.
	// nonLeader is a thread that is not the group's leader (this one, or a sibling): its top-level /proc/<tid>, which
	// readdir hides, is a pid directory of its own, another inode than /proc/<tgid>/task/<tid>.
	sibling, nonLeader := "", ""
	if ents, err := os.ReadDir("/proc/self/task"); err == nil {
		for _, e := range ents {
			if sibling == "" && e.Name() != strconv.Itoa(tid) {
				sibling = e.Name()
			}
			if nonLeader == "" && e.Name() != strconv.Itoa(pid) {
				nonLeader = e.Name()
			}
		}
	}
	self := strconv.Itoa(pid)
	for _, c := range []struct {
		path   string
		want   unix.Errno // 0: reached
		unsure bool
	}{
		{"/proc/" + other + "/cwd/absent", unix.EACCES, true},
		{"/proc/" + other + "/cwd/absent/x", unix.EACCES, true},
		{"/proc/" + other + "/cwd/present", 0, true},
		{"/proc/" + other + "/task/" + other + "/cwd/absent", unix.EACCES, true},
		{"/proc/" + other + "/fd/3/absent", unix.EACCES, true},
		{"/proc/" + other + "/fd/3/present", 0, true},
		{"/proc/" + other + "/root" + dir + "/absent", unix.EACCES, true},
		{"/proc/" + other + "/ns/mnt/x", unix.EACCES, true},
		{"/proc/self/fd/" + fd + "/absent", unix.ENOENT, false},
		{"/proc/self/fd/" + fd + "/present", 0, false},
		{"/dev/fd/" + fd + "/absent", unix.ENOENT, false},
		{"/proc/thread-self/fd/" + fd + "/absent", unix.ENOENT, false},
		{"/proc/" + self + "/fd/" + fd + "/present", 0, false},
		{"/proc/" + self + "/root" + dir + "/absent", unix.ENOENT, false},
		{"/proc/" + self + "/task/" + strconv.Itoa(tid) + "/fd/" + fd + "/absent", unix.ENOENT, false},
		{"/proc/self/cwd/tego-no-such-name", unix.ENOENT, false},
		{"/proc/self/ns/mnt/x", unix.ENOTDIR, false},
		{"/proc/" + self + "/task/" + sibling + "/fd/" + fd + "/present", 0, false},
		{"/proc/" + self + "/task/" + sibling + "/cwd/tego-no-such-name", unix.ENOENT, false},
		{"/proc/" + nonLeader + "/cwd/tego-no-such-name", unix.ENOENT, false},
		{"/proc/" + nonLeader + "/cwd/tego-no-such-name/x", unix.ENOENT, false},
		{"/proc/" + nonLeader + "/root" + dir + "/absent", unix.ENOENT, false},
		{"/proc/" + nonLeader + "/fd/" + fd + "/absent", unix.ENOENT, false},
		{"/proc/" + nonLeader + "/fd/" + fd + "/present", 0, false},
		{"/proc/" + nonLeader + "/task/" + strconv.Itoa(tid) + "/cwd/tego-no-such-name", unix.ENOENT, false},
		{"/proc/" + nonLeader + "/task/" + strconv.Itoa(tid) + "/fd/" + fd + "/absent", unix.ENOENT, false},
	} {
		t.Run(c.path, func(t *testing.T) {
			if strings.Contains(c.path, "/task//") || strings.HasPrefix(c.path, "/proc//") {
				t.Skip("no other thread in this process")
			}
			img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: c.path, joined: c.path})
			switch {
			case c.want == 0 && err != nil:
				t.Fatalf("%v, want the walk to reach the file", err)
			case c.want != 0 && !errors.Is(err, c.want):
				t.Fatalf("%v, want %v", err, c.want)
			case c.want == 0 && img.unsure != c.unsure:
				t.Errorf("unsure = %v, want %v", img.unsure, c.unsure)
			}
		})
	}
}

// TestExecImageProcDirsOfAnotherProcessAreUnsure on procfs: a procfs directory whose mode
// bits let every class search it can still refuse the task by asking who the caller is. /proc/<pid>/fdinfo is 0555,
// and its permission operation asks ptrace_may_access, which the task fails for a root process when it is another
// user and for any process outside its Landlock domain; a pid directory under hidepid asks whether the caller may see
// the process. The walk took those bits as sure (tiers cgroup and bpflsm) or made no check at all (tier landlock),
// following them with its own rights, so a miss in another process's fdinfo was ENOENT with no line where the kernel
// answers the task EACCES: the agent learned which descriptors that process holds open. A procfs directory of another
// thread group, its pid directory or any directory beneath it, is now an unsure step at every tier, as its magic links
// are: a walk through it that fails is EACCES, one that reaches a file says it was unsure. The task's own thread
// group's directories, a non-leader thread's top-level /proc/<tid> included, and procfs directories that belong to no
// process (/proc itself, /proc/sys) are sure as before. The task is this test, with and without the search check; the
// other process is a sleep holding a descriptor 3.
func TestExecImageProcDirsOfAnotherProcessAreUnsure(t *testing.T) {
	tid := selfTask(t)
	modeBitsTempDirs(t)
	pid := os.Getpid()
	me, err := sys.ReadTaskCreds(tid)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	other := strconv.Itoa(spawnTask(t, dir, d))
	fd := strconv.Itoa(int(d.Fd()))
	nonLeader := ""
	if ents, err := os.ReadDir("/proc/self/task"); err == nil {
		for _, e := range ents {
			if e.Name() != strconv.Itoa(pid) {
				nonLeader = e.Name()
				break
			}
		}
	}
	self, me1 := strconv.Itoa(pid), strconv.Itoa(tid)
	prevCreds, prevChecked := taskCreds, searchChecked
	t.Cleanup(func() { taskCreds, searchChecked = prevCreds, prevChecked })
	taskCreds = func(int) (sys.TaskCreds, error) { return me, nil }
	for _, checked := range []bool{false, true} {
		for _, c := range []struct {
			path   string
			want   unix.Errno // 0: reached
			unsure bool
		}{
			{"/proc/" + other + "/fdinfo/tego-no-such-fd", unix.EACCES, true},
			{"/proc/" + other + "/fdinfo/3", 0, true},
			{"/proc/" + other + "/fdinfo/3/x", unix.EACCES, true},
			{"/proc/" + other + "/task/" + other + "/fdinfo/tego-no-such-fd", unix.EACCES, true},
			{"/proc/" + other + "/task/tego-no-such-name", unix.EACCES, true},
			{"/proc/" + other + "/tego-no-such-name", unix.EACCES, true},
			{"/proc/" + other + "/stat", 0, true},
			{"/proc/self/fdinfo/tego-no-such-fd", unix.ENOENT, false},
			{"/proc/self/fdinfo/" + fd, 0, false},
			{"/proc/self/status/x", unix.ENOTDIR, false},
			{"/proc/self/fdinfo/" + fd + "/x", unix.ENOTDIR, false},
			{"/proc/" + self + "/fdinfo/tego-no-such-fd", unix.ENOENT, false},
			{"/proc/" + self + "/task/" + me1 + "/fdinfo/tego-no-such-fd", unix.ENOENT, false},
			{"/proc/" + nonLeader + "/fdinfo/tego-no-such-fd", unix.ENOENT, false},
			{"/proc/" + nonLeader + "/fdinfo/" + fd, 0, false},
			{"/proc/tego-no-such-name", unix.ENOENT, false},
			{"/proc/sys/tego-no-such-name", unix.ENOENT, false},
			{"/proc/sys/kernel/tego-no-such-name", unix.ENOENT, false},
		} {
			t.Run(fmt.Sprintf("checked=%v%s", checked, c.path), func(t *testing.T) {
				if strings.HasPrefix(c.path, "/proc//") {
					t.Skip("no thread but the leader in this process")
				}
				searchChecked = func() bool { return checked }
				img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: c.path, joined: c.path})
				switch {
				case c.want == 0 && err != nil:
					t.Fatalf("%v, want the walk to reach the file", err)
				case c.want != 0 && !errors.Is(err, c.want):
					t.Fatalf("%v, want %v", err, c.want)
				case c.want == 0 && img.unsure != c.unsure:
					t.Errorf("unsure = %v, want %v", img.unsure, c.unsure)
				}
			})
		}
	}
}

// TestExecImageServerFSDirectoriesAreUnsure: on a filesystem whose permission operation is
// its own (FUSE without default_permissions, NFS, SMB, Ceph), the daemon or the server decides each lookup by the
// caller's credentials (NFSv4's ACCESS call, an NFSv4 ACL that system.posix_acl_access does not show), so mode bits
// that let every class search a directory there do not make it searchable for the task. The search check answered
// such a directory sure from its 0755 bits before it asked which filesystem it was on, and a root supervisor's miss
// there (ENOENT, no line) told the task whether a name exists in a directory the server refuses it, where the kernel
// answers EACCES. Such a directory is now unsure whatever its bits: a failed walk is EACCES, a reached file says it
// was unsure. Without the check (tier landlock, where the supervisor's lookups carry the agent's own credentials to the
// same server) nothing changes. The filesystem type is stood in for by dirFSType.
//
// That list was open. kAFS (afs_permission asks the cell with the caller's key), 9p mounted
// access=user (a per-uid attach walks the server as the caller), Coda (coda_permission asks venus) and eCryptfs (its
// permission operation asks the lower inode as the caller) were sure on 0755 bits, and so was every filesystem nobody
// listed (ZFS, out of tree, whose permission operation is not read here). The check is now sure only on a closed
// list of filesystems whose permission operation is generic_permission over the mode bits and access ACL read here
// (modeBitsFS); every other directory is unsure whatever its bits. Each listed filesystem keeps its sure answer, and
// the other directories of the walk are stood in for as ext4, so the test does not depend on the filesystem TMPDIR
// lies on.
func TestExecImageServerFSDirectoriesAreUnsure(t *testing.T) {
	tid := selfTask(t)
	me, err := sys.ReadTaskCreds(tid)
	if err != nil {
		t.Fatal(err)
	}
	other := me
	other.FSUID, other.EUID, other.FSGID, other.EGID, other.Groups, other.CapEff = me.FSUID+1, me.EUID+1, me.FSGID+1, me.EGID+1, nil, 0
	base := t.TempDir()
	for _, sub := range []string{"server", "local"} {
		p := filepath.Join(base, sub)
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "present"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var serverSt unix.Stat_t
	if err := unix.Stat(filepath.Join(base, "server"), &serverSt); err != nil {
		t.Fatal(err)
	}
	baseFD, err := unix.Open(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(baseFD) })
	prevCreds, prevChecked, prevFS := taskCreds, searchChecked, dirFSType
	t.Cleanup(func() { taskCreds, searchChecked, dirFSType = prevCreds, prevChecked, prevFS })
	taskCreds = func(int) (sys.TaskCreds, error) { return other, nil }
	const zfsSuperMagic, unknownMagic = 0x2fc12fc1, 0x12345678
	unsure := []uint32{
		unix.FUSE_SUPER_MAGIC, unix.NFS_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC, unix.SMB2_SUPER_MAGIC, unix.CEPH_SUPER_MAGIC,
		unix.AFS_FS_MAGIC, unix.AFS_SUPER_MAGIC, unix.V9FS_MAGIC, unix.CODA_SUPER_MAGIC, unix.ECRYPTFS_SUPER_MAGIC,
		zfsSuperMagic, unknownMagic,
	}
	sure := []uint32{
		unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, unix.TMPFS_MAGIC,
		unix.RAMFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.SQUASHFS_MAGIC, unix.EROFS_SUPER_MAGIC_V1,
		unix.ISOFS_SUPER_MAGIC, unix.MSDOS_SUPER_MAGIC, unix.EXFAT_SUPER_MAGIC,
	}
	for _, fs := range []struct {
		magics []uint32
		sure   bool
	}{{unsure, false}, {sure, true}} {
		for _, magic := range fs.magics {
			dirFSType = func(fd int) (uint32, error) {
				var st unix.Stat_t
				if unix.Fstat(fd, &st) == nil && st.Dev == serverSt.Dev && st.Ino == serverSt.Ino {
					return magic, nil
				}
				return unix.EXT4_SUPER_MAGIC, nil
			}
			absent := unix.EACCES
			if fs.sure {
				absent = unix.ENOENT
			}
			for _, c := range []struct {
				checked bool
				path    string
				want    unix.Errno // 0: reached
				unsure  bool
			}{
				{true, "server/absent", absent, false},
				{true, "server/absent/x", absent, false},
				{true, "server/present", 0, !fs.sure},
				{true, "local/absent", unix.ENOENT, false},
				{true, "local/present", 0, false},
				{false, "server/absent", unix.ENOENT, false},
				{false, "server/present", 0, false},
			} {
				t.Run(fmt.Sprintf("%#x/checked=%v/%s", magic, c.checked, c.path), func(t *testing.T) {
					checked := c.checked
					searchChecked = func() bool { return checked }
					img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: int32(baseFD), path: c.path, joined: filepath.Join(base, c.path)})
					switch {
					case c.want == 0 && err != nil:
						t.Fatalf("%v, want the walk to reach the file", err)
					case c.want != 0 && !errors.Is(err, c.want):
						t.Fatalf("%v, want %v", err, c.want)
					case c.want == 0 && img.unsure != c.unsure:
						t.Errorf("unsure = %v, want %v", img.unsure, c.unsure)
					}
				})
			}
		}
	}
}

// TestExecImageAutofsFailureIsNoMiss, on the walk: a lookup that fails at an automount
// point, an autofs directory or any S_AUTOMOUNT stub, stood in for here by a directory
// atAutomount is told about, keeps its errno, ENOENT, but is no miss (execMissing), since the kernel's own walk mounts
// the idle automount point this walk landed on; a failure anywhere else is a miss as before, and a walk that reaches a
// file through such a directory is not touched. A real stub, debugfs's tracing, is
// TestExecImageAutomountPointFailureIsNoMiss in the guest.
func TestExecImageAutofsFailureIsNoMiss(t *testing.T) {
	tid := selfTask(t)
	base := t.TempDir()
	auto := filepath.Join(base, "auto")
	if err := os.Mkdir(auto, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auto, "present"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var autoSt unix.Stat_t
	if err := unix.Stat(auto, &autoSt); err != nil {
		t.Fatal(err)
	}
	prev := atAutomount
	t.Cleanup(func() { atAutomount = prev })
	atAutomount = func(fd int) bool {
		var st unix.Stat_t
		return unix.Fstat(fd, &st) == nil && st.Dev == autoSt.Dev && st.Ino == autoSt.Ino
	}
	for _, c := range []struct {
		path   string
		autofs bool
	}{
		{filepath.Join(auto, "absent"), true},
		{filepath.Join(auto, "absent", "x"), true},
		{filepath.Join(base, "absent"), false},
	} {
		_, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: c.path, joined: c.path})
		var a automountLookup
		if !errors.Is(err, unix.ENOENT) || errors.As(err, &a) != c.autofs || execMissing(err) == c.autofs {
			t.Errorf("%s: %v (autofs %v, miss %v), want ENOENT, autofs %v", c.path, err, errors.As(err, &a), execMissing(err), c.autofs)
		}
		if lookupErrno(err) != unix.ENOENT || !execLookupFailure(err) {
			t.Errorf("%s: answered %v, a lookup failure %v; want ENOENT, true", c.path, lookupErrno(err), execLookupFailure(err))
		}
	}
	if _, err := (sysKernel{}).ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: filepath.Join(auto, "present")}); err != nil {
		t.Errorf("a file in an autofs directory: %v", err)
	}
}

// TestExecImageDotDotOutOfAnAutomountStubIsNoMiss: the walk took a failed name lookup at
// an automount point for no miss, but not a failed ".." step out of one. An idle NFS crossmnt or referral stub has no
// lookup operation, so the kernel fails any lookup that starts from it, ".." included, with ENOTDIR (path_init's
// d_can_lookup), and the walk, which lands on the stub without mounting it, failed "sub/../tool" there: ENOTDIR, a miss
// with no line, where the kernel's own walk mounts the submount as an intermediate component, climbs back out of it and
// finds the tool. At tier landlock nothing else turned that into a decided exec (at the root tiers NFS is outside
// modeBitsFS and the walk was unsure, so it was EACCES). A ".." that fails at an automount point is now no miss either:
// it keeps its errno, ENOTDIR, and is decided and recorded. The stub is stood in for by a regular file atAutomount is
// told about, since a lookup from a file fails ".." with ENOTDIR as one from the stub does; the same step out of a
// file atAutomount is not told about is still a miss.
func TestExecImageDotDotOutOfAnAutomountStubIsNoMiss(t *testing.T) {
	tid := selfTask(t)
	modeBitsTempDirs(t)
	base := t.TempDir()
	for _, name := range []string{"stub", "plain", "tool"} {
		if err := os.WriteFile(filepath.Join(base, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("stub", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	var stubSt unix.Stat_t
	if err := unix.Stat(filepath.Join(base, "stub"), &stubSt); err != nil {
		t.Fatal(err)
	}
	prev, prevChecked := atAutomount, searchChecked
	t.Cleanup(func() { atAutomount, searchChecked = prev, prevChecked })
	atAutomount = func(fd int) bool {
		var st unix.Stat_t
		return unix.Fstat(fd, &st) == nil && st.Dev == stubSt.Dev && st.Ino == stubSt.Ino
	}
	for _, checked := range []bool{false, true} {
		for _, c := range []struct {
			path      string
			automount bool
		}{
			{"stub/../tool", true},
			{"link/../tool", true}, // the link is read, and its target's ".." is the step that fails
			{"plain/../tool", false},
		} {
			t.Run(fmt.Sprintf("checked=%v/%s", checked, c.path), func(t *testing.T) {
				searchChecked = func() bool { return checked }
				p := base + "/" + c.path // uncleaned: filepath.Join would drop the ".." step under test
				_, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: filepath.Clean(p)})
				var a automountLookup
				if !errors.Is(err, unix.ENOTDIR) || errors.As(err, &a) != c.automount || execMissing(err) == c.automount {
					t.Errorf("%v (at an automount point %v, a miss %v), want ENOTDIR, at an automount point %v",
						err, errors.As(err, &a), execMissing(err), c.automount)
				}
				if lookupErrno(err) != unix.ENOTDIR || !execLookupFailure(err) {
					t.Errorf("answered %v, a lookup failure %v; want ENOTDIR, true", lookupErrno(err), execLookupFailure(err))
				}
			})
		}
	}
}

// TestSearchCheckedMeansTheSupervisorBypassesDAC: the check is made where this process's lookups can pass a directory
// the task's cannot, and only there: a process holding CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH (root at tiers cgroup
// and bpflsm) checks, an unprivileged one (tier landlock, the agent's own credentials) does not.
func TestSearchCheckedMeansTheSupervisorBypassesDAC(t *testing.T) {
	c, err := sys.ReadTaskCreds(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	want := c.CapEff&(1<<unix.CAP_DAC_OVERRIDE|1<<unix.CAP_DAC_READ_SEARCH) != 0
	if got := searchChecked(); got != want {
		t.Errorf("searchChecked() = %v with CapEff %#x, want %v", got, c.CapEff, want)
	}
}

// BenchmarkExecImageSearchCheck is the search check's cost on a PATH search's walk, as a root supervisor makes it for
// an agent of another user: /usr/local/bin/<name> (a miss) and /usr/bin/env (a hit), with the check off (tier
// landlock) and on (tiers cgroup and bpflsm).
func BenchmarkExecImageSearchCheck(b *testing.B) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := unix.Gettid()
	me, err := sys.ReadTaskCreds(tid)
	if err != nil {
		b.Fatal(err)
	}
	other := me
	other.FSUID, other.FSGID, other.Groups, other.CapEff = me.FSUID+1, me.FSGID+1, nil, 0
	prevCreds, prevChecked := taskCreds, searchChecked
	b.Cleanup(func() { taskCreds, searchChecked = prevCreds, prevChecked })
	taskCreds = func(int) (sys.TaskCreds, error) { return other, nil }
	for _, checked := range []bool{false, true} {
		for _, p := range []string{"/usr/local/bin/tego-no-such-name", "/usr/bin/env"} {
			name := "off"
			if checked {
				name = "on"
			}
			b.Run(name+p, func(b *testing.B) {
				searchChecked = func() bool { return checked }
				b.ReportAllocs()
				for b.Loop() {
					_, _ = sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p})
				}
			})
		}
	}
}
