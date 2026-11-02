// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// GuardedStdioLeakCheckMain is GuardedLeakCheckMain that also fails the binary when a test closed or replaced
// descriptor 0, 1 or 2: one names another file, or none, after the tests than before them. A runner a test built by
// hand with its notify descriptor at the zero value closed the binary's stdin on shutdown, the next file any test
// opened became descriptor 0, and sys.Own's refusal of a standard number (ADR 0023) then failed whichever unrelated
// test opened it. The check names the closing package at once instead.
//
// A binary started as go test starts it runs its tests in a guarded child (GuardedMain), whose own TestMain makes the
// same call: the check that counts is the child's, around the m.Run that ran the tests.
func GuardedStdioLeakCheckMain(m *testing.M) int {
	return stdioCheckAfter(func() int { return GuardedLeakCheckMain(m) }, os.Stderr)
}

// stdioCheckAfter runs the tests and returns their code, or 1 (theirs when it is already non-zero) when descriptor
// 0, 1 or 2 changed meanwhile, which it writes to stderr.
func stdioCheckAfter(run func() int, stderr io.Writer) int {
	before := stdioIdentity()
	code := run()
	if now := stdioIdentity(); now != before {
		_, _ = fmt.Fprintf(stderr, "FAIL: a test closed or replaced a standard descriptor: before %v, after %v\n", before, now)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// stdioIdentity is what descriptors 0, 1 and 2 are open on: device and inode, or the fstat error.
func stdioIdentity() [3]string {
	var out [3]string
	for n := range out {
		var st unix.Stat_t
		if err := unix.Fstat(n, &st); err != nil {
			out[n] = err.Error()
			continue
		}
		out[n] = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	return out
}
