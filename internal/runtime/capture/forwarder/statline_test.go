// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
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

// TestARequestAskReadsAReleasedStatLineAgain: a held request's approval is keyed by its sender's pid and start, so
// a reused pid never inherits one. A line of a task released while it was read was refused as malformed, so the
// request was refused unavailable for a process whose next read is its own live line. requestAskIdentity now reads
// again (proc.ReadStat): a live process gets the key its live line gives, a gone one (ENOENT) and a line that
// stays released are still refused, so no approval is ever keyed to a process that vanished.
func TestARequestAskReadsAReleasedStatLineAgain(t *testing.T) {
	r, err := http.NewRequest("POST", "https://fixed.example/allowed", nil)
	if err != nil {
		t.Fatal(err)
	}
	key := func() ([32]byte, error) {
		return requestAskIdentity(r, 842314, "fixed.example:443", "", []byte("body"))
	}

	readsStat(t, []string{liveStat}, []error{nil})
	live, err := key()
	if err != nil {
		t.Fatal(err)
	}
	readsStat(t, []string{deThreadStat, liveStat}, []error{nil, nil})
	if got, err := key(); err != nil || got != live {
		t.Fatalf("key(mid-exec) = %x, %v; want the live line's key %x", got, err, live)
	}
	enoent := fmt.Errorf("open /proc/842314/stat: %w", fs.ErrNotExist)
	readsStat(t, []string{deThreadStat, ""}, []error{nil, enoent})
	if _, err := key(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("key(reaped) = %v; want ENOENT", err)
	}
	readsStat(t, []string{deThreadStat}, []error{nil})
	if _, err := key(); !errors.Is(err, proc.ErrStat) {
		t.Fatalf("key(released on every read) = %v; want ErrStat", err)
	}
}
