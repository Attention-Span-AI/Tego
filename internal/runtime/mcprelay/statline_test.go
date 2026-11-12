// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// deThreadStat is a /proc/<pid>/stat line a reader on kernel 6.17 caught for a live process whose old leader an
// execve from another of its threads released (de_thread): ppid 0, process group and session -1, num_threads 0
// (internal/platform/proc's deThreadStatLine). liveStat is the line the next read of that process gave.
const (
	deThreadStat = "842314 (exe) Z 0 -1 -1 0 -1 4228108 40251 0 0 0 4 27 0 0 20 0 0 0 82606841 0 0 0 0 0 0 0 " +
		"0 0 0 0 0 1 0 0 -1 6 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
	liveStat = "842314 (exe) S 842312 842312 842312 0 -1 4194304 100 0 0 0 5 6 0 0 20 0 1 0 82606841 0 0 0\n"
)

// readsStat stands lines (or errors) in for readProcStat, one per read; the last repeats.
func readsStat(t *testing.T, lines []string, errs []error) {
	t.Helper()
	old, n := readProcStat, 0
	readProcStat = func(int) ([]byte, error) {
		i := min(n, len(lines)-1)
		n++
		return []byte(lines[i]), errs[i]
	}
	t.Cleanup(func() { readProcStat = old })
}

// TestAReleasedStatLineIsReadAgain: startOf and ppidOf name the shim by its start and its parent. A line of a task
// released while it was read has ppid 0 and process group -1: read by hand, ppidOf answered 0, and startOf refused
// it as malformed, for a process whose next read is its own live line. They now read again (proc.ReadStat): a live
// process is its live line, a gone one read's own error, and a line that stays released is still refused.
func TestAReleasedStatLineIsReadAgain(t *testing.T) {
	enoent := fmt.Errorf("open /proc/842314/stat: %w", fs.ErrNotExist)

	readsStat(t, []string{deThreadStat, liveStat}, []error{nil, nil})
	if start, err := startOf(842314); err != nil || start != 82606841 {
		t.Fatalf("startOf(mid-exec) = %d, %v; want the live line's 82606841", start, err)
	}
	readsStat(t, []string{deThreadStat, liveStat}, []error{nil, nil})
	if ppid := ppidOf(842314); ppid != 842312 {
		t.Fatalf("ppidOf(mid-exec) = %d; want the live line's 842312", ppid)
	}
	readsStat(t, []string{deThreadStat, ""}, []error{nil, enoent})
	if start, err := startOf(842314); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("startOf(reaped) = %d, %v; want ENOENT", start, err)
	}
	readsStat(t, []string{deThreadStat}, []error{nil})
	if start, err := startOf(842314); !errors.Is(err, proc.ErrStat) {
		t.Fatalf("startOf(released on every read) = %d, %v; want ErrStat", start, err)
	}
	if ppid := ppidOf(842314); ppid != 0 {
		t.Fatalf("ppidOf(released on every read) = %d; want 0", ppid)
	}
}
