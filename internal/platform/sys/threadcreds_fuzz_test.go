// SPDX-License-Identifier: Apache-2.0

package sys

import "testing"

// FuzzParseStatusCreds feeds the /proc/<tid>/status credential parser arbitrary bytes. It must never panic, and an
// error never comes with credentials: a zero read as root is the one wrong answer that grants.
func FuzzParseStatusCreds(f *testing.F) {
	f.Add([]byte("Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\nGroups:\t1 2 3\n"))
	f.Add([]byte("Uid:\t1\t2\t3\n"))
	f.Add([]byte("Uid:\t-1\t2\t3\t4\nGid:\t1\t2\t3\t4\n"))
	f.Add([]byte("Uid:\t99999999999\t2\t3\t4\n"))
	f.Add([]byte("Groups:\t\nUid:\t0\t0\t0\t0\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseStatusCreds(b)
		if err != nil && (c.EUID != 0 || c.FSUID != 0 || c.EGID != 0 || c.FSGID != 0 || len(c.Groups) != 0) {
			t.Fatalf("error %v with credentials %+v", err, c)
		}
	})
}
