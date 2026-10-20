// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"fmt"
	"testing"
)

// FuzzProcLocks feeds the /proc/locks parser arbitrary bytes: kernel text that a re-arm pass reads to tell whether a
// build's timer lives (ADR 0022, note 2026-10-06). It must never panic, never return more locks than the input has
// lines, and every lock it returns must be what its own line, printed back as the kernel prints a held flock, parses
// to.
func FuzzProcLocks(f *testing.F) {
	f.Add([]byte("1: FLOCK  ADVISORY  WRITE 1234 00:1a:5678 0 EOF\n"))
	f.Add([]byte("1: FLOCK  ADVISORY  WRITE 1234 00:1a:5678 0 EOF\n1: -> FLOCK  ADVISORY  WRITE 4321 00:1a:5678 0 EOF\n"))
	f.Add([]byte("2: POSIX  ADVISORY  READ 787335 103:02:11156029 128 128\n3: FLOCK  ADVISORY  READ 9 fd:01:42 0 EOF"))
	f.Add([]byte("4: OFDLCK ADVISORY  WRITE -1 00:05:12 0 EOF\n5: LEASE  ACTIVE    READ 77 00:1a:3 0 EOF\n"))
	f.Add([]byte("6: FLOCK  ADVISORY  WRITE 0 <none>:0 0 EOF\n7:  -> FLOCK  ADVISORY  READ 5 103:02:9 0 EOF\n"))
	f.Add([]byte("8: FLOCK  ADVISORY  WRITE 12 ffffffff:ffffffff:18446744073709551615 0 EOF"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		locks := parseProcLocks(b)
		if len(locks) > bytes.Count(b, []byte{'\n'})+1 {
			t.Fatalf("%d locks from %d lines", len(locks), bytes.Count(b, []byte{'\n'})+1)
		}
		for _, l := range locks {
			kind := "READ"
			if l.write {
				kind = "WRITE"
			}
			line := fmt.Sprintf("1: FLOCK  ADVISORY  %s %d %02x:%02x:%d 0 EOF", kind, l.pid, l.major, l.minor, l.ino)
			again, ok := parseProcLock(line)
			if !ok || again != l {
				t.Fatalf("lock %+v prints as %q, which parses to %+v (%v)", l, line, again, ok)
			}
		}
	})
}
