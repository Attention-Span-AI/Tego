// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// performAttr performs space 4's attribute and node ops (ADR 0017 space 4: the deny_write ancestors), or reports
// the op unknown.
func performAttr(a Action) error {
	switch a.Op {
	case "chown": // to the owner and group the file has when the agent made it: path_chown runs all the same
		return unix.Chown(a.Path, os.Getuid(), os.Getgid())
	case "setxattr":
		return unix.Setxattr(a.Path, "user.tego", []byte("x"), 0)
	case "setfacl": // setfacl's own call: the access ACL as its xattr, here the minimal ACL of mode 0640
		return unix.Setxattr(a.Path, "system.posix_acl_access", minimalACL(6, 4, 0), 0)
	case "mknod": // a FIFO, the node an unprivileged agent can make
		return unix.Mknod(a.Path, unix.S_IFIFO|0o644, 0)
	}
	return fmt.Errorf("unknown op %q", a.Op)
}

// minimalACL is a POSIX access ACL in the kernel's xattr format (posix_acl_xattr.h: a version-2 header, then
// {tag u16, perm u16, id u32} entries) with only the owner, group and other entries, which the kernel stores as the
// file's mode bits: so setfacl changes the mode without chmod (inode_set_acl from 6.2).
func minimalACL(user, group, other uint16) []byte {
	const (
		version  = 2
		userObj  = 0x01
		groupObj = 0x04
		otherTag = 0x20
		undefID  = 0xffffffff
	)
	b := binary.LittleEndian.AppendUint32(nil, version)
	for _, e := range [][2]uint16{{userObj, user}, {groupObj, group}, {otherTag, other}} {
		b = binary.LittleEndian.AppendUint16(b, e[0])
		b = binary.LittleEndian.AppendUint16(b, e[1])
		b = binary.LittleEndian.AppendUint32(b, undefID)
	}
	return b
}
