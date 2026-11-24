// SPDX-License-Identifier: Apache-2.0

//go:build linux

package pricetable

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// fileStamps is the stamps of one stat: device, inode, size, mtime and ctime in nanoseconds, and the newest of the two
// times. ok is false when the stat carries no such stamps.
func fileStamps(st os.FileInfo) (stamps string, newest time.Time, ok bool) {
	s, isStat := st.Sys().(*syscall.Stat_t)
	if !isStat {
		return fmt.Sprintf("size:%d", st.Size()), st.ModTime(), false
	}
	m := time.Unix(int64(s.Mtim.Sec), int64(s.Mtim.Nsec))
	c := time.Unix(int64(s.Ctim.Sec), int64(s.Ctim.Nsec))
	newest = m
	if c.After(m) {
		newest = c
	}
	return fmt.Sprintf("dev:%d ino:%d size:%d mtime:%d ctime:%d", uint64(s.Dev), s.Ino, s.Size, m.UnixNano(), c.UnixNano()), newest, true
}
