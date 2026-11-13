// SPDX-License-Identifier: Apache-2.0

package agent

import "golang.org/x/sys/unix"

// KernelFS is a kernel filesystem whose files are interfaces to the kernel or to other processes, not stored data:
// its statfs magic, the type /proc/self/mountinfo gives its mounts ("" for one the kernel never mounts by name), and
// whether R10 refuses a write grant that reaches it (ADR 0059, second amendment of 2026-11-11).
type KernelFS struct {
	Magic int64
	Type  string
	// WriteRefused is R10's policy for a write grant that reaches a mount of it; Why says why a type is not refused.
	WriteRefused bool
	Why          string
}

// KernelFilesystems is the one inventory of kernel interface filesystems: compile's write-grant refusal by mount type
// (mountTable.controlFS) and the supervisor's alternate-file refusal by statfs magic (supervisor pseudoFS) read it.
// boundedio has a separate table for diagnostic names. Several magics have no constant in x/sys and are spelled as
// linux/magic.h does.
// What is not listed (ext4, tmpfs, overlay, FUSE, hugetlbfs, devtmpfs and every other) is not one of these.
var KernelFilesystems = []KernelFS{
	{Magic: unix.PROC_SUPER_MAGIC, Type: "proc", WriteRefused: true},
	{Magic: unix.SYSFS_MAGIC, Type: "sysfs", WriteRefused: true},
	{Magic: unix.CGROUP_SUPER_MAGIC, Type: "cgroup", WriteRefused: true},
	{Magic: unix.CGROUP2_SUPER_MAGIC, Type: "cgroup2", WriteRefused: true},
	{Magic: unix.BPF_FS_MAGIC, Type: "bpf", WriteRefused: true},
	{Magic: unix.DEBUGFS_MAGIC, Type: "debugfs", WriteRefused: true},
	{Magic: unix.TRACEFS_MAGIC, Type: "tracefs", WriteRefused: true},
	{Magic: unix.SECURITYFS_MAGIC, Type: "securityfs", WriteRefused: true},
	{Magic: unix.SELINUX_MAGIC, Type: "selinuxfs", WriteRefused: true},
	{Magic: unix.SMACK_MAGIC, Type: "smackfs", WriteRefused: true},
	{Magic: unix.AAFS_MAGIC, Type: "apparmorfs", WriteRefused: true},
	{Magic: unix.EFIVARFS_MAGIC, Type: "efivarfs", WriteRefused: true},
	{Magic: unix.PSTOREFS_MAGIC, Type: "pstore", WriteRefused: true},
	{Magic: unix.BINFMTFS_MAGIC, Type: "binfmt_misc", WriteRefused: true},
	{Magic: unix.RDTGROUP_SUPER_MAGIC, Type: "resctrl", WriteRefused: true},
	{Magic: unix.NSFS_MAGIC, Type: "nsfs", WriteRefused: true},
	{Magic: unix.BINDERFS_SUPER_MAGIC, Type: "binder", WriteRefused: true},
	{Magic: unix.USBDEVICE_SUPER_MAGIC, Type: "usbfs", WriteRefused: true},
	{Magic: 0x62656570, Type: "configfs", WriteRefused: true},
	{Magic: 0x65735543, Type: "fusectl", WriteRefused: true},
	{Magic: 0x19800202, Type: "mqueue", WriteRefused: true},
	{Magic: 0x67596969, Type: "rpc_pipefs", WriteRefused: true},
	{Magic: unix.XENFS_SUPER_MAGIC, Type: "xenfs", WriteRefused: true},
	{Magic: 0xa647361, Type: "functionfs", WriteRefused: true},
	{Magic: unix.DEVPTS_SUPER_MAGIC, Type: "devpts", Why: "an agent's own pseudo-terminals are opened through it (shipped " +
		"Codex contracts grant /dev/pts/); ADR 0113's terminal layer excludes other slaves there, and compile refuses " +
		"devpts mounts at other paths because that layer grants ordinary directories recursively"},
	// Never mounted by name: a descriptor's filesystem, not a path's, so no grant reaches one.
	{Magic: unix.PID_FS_MAGIC, Type: "", WriteRefused: true},
	{Magic: unix.ANON_INODE_FS_MAGIC, Type: "", WriteRefused: true},
	{Magic: unix.SOCKFS_MAGIC, Type: "", WriteRefused: true},
	{Magic: unix.PIPEFS_MAGIC, Type: "", WriteRefused: true},
	{Magic: unix.SECRETMEM_MAGIC, Type: "", WriteRefused: true},
	{Magic: unix.DMA_BUF_MAGIC, Type: "", WriteRefused: true},
	{Magic: unix.BDEVFS_MAGIC, Type: "", WriteRefused: true},
	{Magic: unix.DEVMEM_MAGIC, Type: "", WriteRefused: true},
}

// KernelFSName is the name of the kernel filesystem with statfs magic m ("" when it is not one): its mount type, or
// for one never mounted by name the supervisor's own word.
func KernelFSName(m int64) string {
	for _, k := range KernelFilesystems {
		if k.Magic == m {
			if k.Type != "" {
				return k.Type
			}
			return kernelFSInternal[m]
		}
	}
	return ""
}

// kernelFSInternal names the filesystems never mounted by name, for messages.
var kernelFSInternal = map[int64]string{
	unix.PID_FS_MAGIC: "pidfs", unix.ANON_INODE_FS_MAGIC: "anon_inodefs", unix.SOCKFS_MAGIC: "sockfs",
	unix.PIPEFS_MAGIC: "pipefs", unix.SECRETMEM_MAGIC: "secretmem", unix.DMA_BUF_MAGIC: "dmabuf",
	unix.BDEVFS_MAGIC: "bdev", unix.DEVMEM_MAGIC: "devmem",
}

// writeRefusedType reports whether R10 refuses a write grant that reaches a mount of mountinfo type t.
func writeRefusedType(t string) bool {
	for _, k := range KernelFilesystems {
		if k.Type == t && t != "" {
			return k.WriteRefused
		}
	}
	return false
}

// memoryFilesystemTypes complements KernelFilesystems for storage warnings only.
// Both backing classes exclude directory storage on these memory mounts.
// Uncertain regular-file binds still warn. Backing folders stored on memory
// are GAPS C65's explicit silent limit. These types
// must not become KernelFSName results: the supervisor admits their data files.
var memoryFilesystemTypes = []string{"tmpfs", "ramfs", "hugetlbfs", "devtmpfs"}

func kernelOrMemoryType(t string) bool {
	for _, k := range KernelFilesystems {
		if k.Type != "" && k.Type == t {
			return true
		}
	}
	for _, m := range memoryFilesystemTypes {
		if m == t {
			return true
		}
	}
	return false
}
