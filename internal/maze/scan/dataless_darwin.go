// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"io/fs"
	"syscall"
)

// sfDataless is macOS's flag for a file whose contents aren't on this disk (iCloud Drive's "Optimize Mac
// Storage" evicted it): only its name is here, and opening it waits for a download that may never come.
const sfDataless = 0x40000000

// dataless reports whether fi is a file whose contents aren't on disk.
func dataless(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}
