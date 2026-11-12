// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"fmt"
	"io/fs"
	"testing"
)

// deThreadStat is a /proc/<pid>/stat line a reader on kernel 6.17 caught for a live process whose old leader an
// execve from another of its threads released (de_thread): state Z, ppid 0, process group and session -1,
// num_threads 0 (internal/platform/proc's deThreadStatLine). liveStat is the line the next read of that process gave.
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

// TestTheReaperReadsAReleasedStatLineAgain: the reaper finds adopted children by their stat's ppid (scanChildren)
// and reaps those whose state is Z, and TakeStop trusts a stop only while the state is T. A line of a task released
// while it was read keeps ppid 0 and the state read before the release, Z for a live process mid-exec (de_thread):
// read by hand it said zombie for a live child and parent 0 for any. procPPid and procStatState now read again
// (proc.ReadStat): a live process is its live line, a gone one (ENOENT) is unreadable, and a line that stays
// released is unreadable too, never a zombie, a stop or a parent.
func TestTheReaperReadsAReleasedStatLineAgain(t *testing.T) {
	enoent := fmt.Errorf("open /proc/842314/stat: %w", fs.ErrNotExist)
	for _, c := range []struct {
		name   string
		lines  []string
		errs   []error
		zombie bool
		ppid   int
		ok     bool
	}{
		{"a live process mid-exec", []string{deThreadStat, liveStat}, []error{nil, nil}, false, 842312, true},
		{"reaped", []string{deThreadStat, ""}, []error{nil, enoent}, false, 0, false},
		{"released on every read", []string{deThreadStat}, []error{nil}, false, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			readsStat(t, c.lines, c.errs)
			if z := procZombie(842314); z != c.zombie {
				t.Errorf("procZombie = %v, want %v", z, c.zombie)
			}
			readsStat(t, c.lines, c.errs)
			if p, ok := procPPid(842314); p != c.ppid || ok != c.ok {
				t.Errorf("procPPid = %d, %v; want %d, %v", p, ok, c.ppid, c.ok)
			}
		})
	}
}
