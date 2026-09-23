// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"io/fs"
	"syscall"
)

// sysIdentity pulls the device and inode numbers out of a FileInfo. It is the one place this package
// touches a platform type; everything else works on any filesystem a test can build.
func sysIdentity(fi fs.FileInfo) (dev, ino uint64, ok bool) {
	st, okCast := fi.Sys().(*syscall.Stat_t)
	if !okCast {
		return 0, 0, false
	}
	return uint64(st.Dev), st.Ino, true
}
