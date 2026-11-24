// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// EIOFile returns the path of a regular file that opens for any process of the user but whose read fails with EIO, as a
// file on a dead network or FUSE mount does. It is for a test of how a read failure of a location is shown, through a
// helper process that has to open it itself.
//
// It is a sysfs attribute, power/autosuspend_delay_ms of a device that has no autosuspend (the kernel answers -EIO to its
// read, whoever reads it). It is not /proc/self/mem, the file that answers EIO at address zero: the helpers are
// undumpable (ADR 0100, amendment 2026-11-22), so the kernel makes every /proc/<pid>/mem root-owned and refuses even the
// helper's own open of it. The test fails, rather than skips, on a kernel with no such attribute, so the check is not
// silently lost: say so in the test's name if a platform is found that has none.
func EIOFile(t testing.TB) string {
	t.Helper()
	for _, pattern := range []string{
		"/sys/devices/*/power/autosuspend_delay_ms",
		"/sys/devices/*/*/power/autosuspend_delay_ms",
		"/sys/devices/*/*/*/power/autosuspend_delay_ms",
	} {
		paths, _ := filepath.Glob(pattern)
		for _, path := range paths {
			if st, err := os.Lstat(path); err != nil || !st.Mode().IsRegular() {
				continue
			}
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			var b [16]byte
			_, err = f.Read(b[:])
			_ = f.Close()
			if errors.Is(err, syscall.EIO) {
				return path
			}
		}
	}
	t.Fatal("this kernel has no regular file that opens and answers EIO to a read (no power/autosuspend_delay_ms of a device without autosuspend)")
	return ""
}
