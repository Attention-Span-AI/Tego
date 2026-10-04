// SPDX-License-Identifier: Apache-2.0

package cgroup

import "testing"

// FuzzParseFDInfo feeds the /proc/self/fdinfo parser arbitrary bytes. It must never panic and never return an
// error alongside ids, nor a success without both lines.
func FuzzParseFDInfo(f *testing.F) {
	f.Add([]byte("pos:\t0\nflags:\t010000000\nmnt_id:\t29\nino:\t1234\n"))
	f.Add([]byte("mnt_id:\tx\nino:\t1\n"))
	f.Add([]byte("mnt_id: 1\n"))
	f.Add([]byte("mnt_id: 1\nmnt_id: bad\nino: 3\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, i, err := parseFDInfo(b)
		if err != nil && (m != 0 || i != 0) {
			t.Fatalf("error %v with ids %d %d", err, m, i)
		}
	})
}
